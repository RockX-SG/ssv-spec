package frost

import (
	"math/rand"

	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/dkg/frost"
	ecies "github.com/ecies/go/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
)

var thisCurve = curves.BLS12381G1()

func init() {
	types.InitBLS()
}

type FROST struct {
	network dkg.Network
	signer  types.DKGSigner
	storage dkg.Storage

	state *State
}

type State struct {
	identifier dkg.RequestID
	operatorID types.OperatorID
	sessionSK  *ecies.PrivateKey

	threshold    uint32
	currentRound DKGRound
	participant  *frost.DkgParticipant

	operators      []uint32
	operatorsOld   []uint32
	operatorShares map[uint32]*bls.SecretKey

	msgs            map[DKGRound]map[uint32]*dkg.SignedMessage
	oldKeyGenOutput *dkg.KeyGenOutput
}

type DKGRound int

const (
	Uninitialized DKGRound = iota
	Preparation
	Round1
	Round2
	KeygenOutput
	Blame
)

func New(
	network dkg.Network,
	operatorID types.OperatorID,
	requestID dkg.RequestID,
	signer types.DKGSigner,
	storage dkg.Storage,
	init *dkg.Init,
) dkg.Protocol {

	msgs := make(map[DKGRound]map[uint32]*dkg.SignedMessage)
	msgs[Preparation] = make(map[uint32]*dkg.SignedMessage)
	msgs[Round1] = make(map[uint32]*dkg.SignedMessage)
	msgs[Round2] = make(map[uint32]*dkg.SignedMessage)
	msgs[Blame] = make(map[uint32]*dkg.SignedMessage)

	fr := &FROST{
		network: network,
		signer:  signer,
		storage: storage,
		state: &State{
			identifier:     requestID,
			operatorID:     operatorID,
			threshold:      uint32(init.Threshold),
			currentRound:   Uninitialized,
			operators:      types.OperatorList(init.OperatorIDs).ToUint32List(),
			operatorShares: make(map[uint32]*bls.SecretKey),
			msgs:           msgs,
		},
	}

	return fr
}

// Temporary, TODO: Remove and use interface with Reshare
func NewResharing(
	network dkg.Network,
	operatorID types.OperatorID,
	requestID dkg.RequestID,
	signer types.DKGSigner,
	storage dkg.Storage,
	oldOperators []types.OperatorID,
	init *dkg.Reshare,
	output *dkg.KeyGenOutput,
) dkg.Protocol {

	msgs := make(map[DKGRound]map[uint32]*dkg.SignedMessage)
	msgs[Preparation] = make(map[uint32]*dkg.SignedMessage)
	msgs[Round1] = make(map[uint32]*dkg.SignedMessage)
	msgs[Round2] = make(map[uint32]*dkg.SignedMessage)
	msgs[Blame] = make(map[uint32]*dkg.SignedMessage)

	operatorsOld := types.OperatorList(oldOperators).ToUint32List()

	return &FROST{
		network: network,
		signer:  signer,
		storage: storage,

		state: &State{
			identifier:      requestID,
			operatorID:      operatorID,
			threshold:       uint32(init.Threshold),
			currentRound:    Uninitialized,
			operators:       types.OperatorList(init.OperatorIDs).ToUint32List(),
			operatorsOld:    operatorsOld,
			operatorShares:  make(map[uint32]*bls.SecretKey),
			msgs:            msgs,
			oldKeyGenOutput: output,
		},
	}
}

// TODO: If Reshare, confirm participating operators using qbft before kick-starting this process.
func (fr *FROST) Start() error {
	fr.state.currentRound = Preparation

	ctx := make([]byte, 16)
	if _, err := rand.Read(ctx); err != nil {
		return err
	}
	participant, err := frost.NewDkgParticipant(uint32(fr.state.operatorID), fr.state.threshold, string(ctx), thisCurve, fr.state.operators...)
	if err != nil {
		return errors.Wrap(err, "failed to initialize a dkg participant")
	}
	fr.state.participant = participant

	if !fr.needToRunThisRound(Preparation) {
		return nil
	}

	k, err := ecies.GenerateKey()
	if err != nil {
		return errors.Wrap(err, "failed to generate session sk")
	}
	fr.state.sessionSK = k

	msg := &ProtocolMsg{
		Round: fr.state.currentRound,
		PreparationMessage: &PreparationMessage{
			SessionPk: k.PublicKey.Bytes(true),
		},
	}
	return fr.broadcastDKGMessage(msg)
}

func (fr *FROST) ProcessMsg(msg *dkg.SignedMessage) (bool, *dkg.ProtocolOutcome, error) {

	if err := fr.validateSignedMessage(msg); err != nil {
		return false, nil, errors.Wrap(err, "failed to validate signed message")
	}

	protocolMessage := &ProtocolMsg{}
	if err := protocolMessage.Decode(msg.Message.Data); err != nil {
		return false, nil, errors.Wrap(err, "failed to decode protocol msg")
	}
	if err := fr.validateProtocolMessage(protocolMessage); err != nil {
		return false, nil, errors.Wrap(err, "failed to validate protocol message")
	}

	originalMessage, ok := fr.state.msgs[protocolMessage.Round][uint32(msg.Signer)]
	if ok && !fr.haveSameRoot(originalMessage, msg) {
		return false, nil, fr.createAndBroadcastBlameOfInconsistentMessage(originalMessage, msg)
	}

	fr.state.msgs[protocolMessage.Round][uint32(msg.Signer)] = msg

	if protocolMessage.Round == Blame {
		out, err := fr.processBlame()
		if err != nil {
			return false, nil, err
		}
		return true, &dkg.ProtocolOutcome{BlameOutput: out}, nil
	}

	switch fr.state.currentRound {
	case Preparation:
		// Received all
		if fr.canProceedThisRound() {
			fr.state.currentRound = Round1
			if err := fr.processRound1(); err != nil {
				return false, nil, err
			}
		}
	case Round1:
		if fr.canProceedThisRound() {
			fr.state.currentRound = Round2
			if err := fr.processRound2(); err != nil {
				if err.Error() == "invalid share" {
					return true, &dkg.ProtocolOutcome{BlameOutput: err.(ErrInvalidShare).BlameOutput}, nil
				}
				return false, nil, err
			}
		}
	case Round2:
		if fr.canProceedThisRound() {
			fr.state.currentRound = KeygenOutput
			out, err := fr.processKeygenOutput()
			if err != nil {
				return false, nil, err
			}
			return true, &dkg.ProtocolOutcome{ProtocolOutput: out}, nil
		}
	default:
		return true, nil, dkg.ErrInvalidRound{}
	}

	return false, nil, nil
}

func (fr *FROST) canProceedThisRound() bool {

	// Preparation (N) -> Round1 (O) -> Round2 (N)
	switch fr.state.currentRound {
	case Preparation:
		return fr.allMessagesReceivedFor(Preparation, fr.state.operators)
	case Round1:
		if fr.isResharing() {
			return fr.allMessagesReceivedFor(Round1, fr.state.operatorsOld)
		} else {
			return fr.allMessagesReceivedFor(Round1, fr.state.operators)
		}
	case Round2:
		return fr.allMessagesReceivedFor(Round2, fr.state.operators)
	}
	return true
}

func (fr *FROST) allMessagesReceivedFor(round DKGRound, operators []uint32) bool {
	for _, operatorID := range operators {
		if _, ok := fr.state.msgs[round][operatorID]; !ok {
			return false
		}
	}
	return true
}

func (fr *FROST) isResharing() bool {
	return len(fr.state.operatorsOld) > 0
}

func (fr *FROST) inOldCommittee() bool {
	for _, id := range fr.state.operatorsOld {
		if types.OperatorID(id) == fr.state.operatorID {
			return true
		}
	}
	return false
}

func (fr *FROST) inNewCommittee() bool {
	for _, id := range fr.state.operators {
		if types.OperatorID(id) == fr.state.operatorID {
			return true
		}
	}
	return false
}

func (fr *FROST) needToRunThisRound(thisRound DKGRound) bool {
	// If new keygen, every round need to run
	if !fr.isResharing() {
		return true
	}
	switch thisRound {
	case Preparation:
		return fr.inNewCommittee()
	case Round1:
		return fr.inOldCommittee()
	case Round2:
		return fr.inNewCommittee()
	case KeygenOutput:
		return fr.inNewCommittee()
	default:
		return false
	}
}

func (fr *FROST) validateSignedMessage(msg *dkg.SignedMessage) error {
	if msg.Message.Identifier != fr.state.identifier {
		return errors.New("got mismatching identifier")
	}

	found, operator, err := fr.storage.GetDKGOperator(msg.Signer)
	if !found {
		return errors.New("unable to find signer")
	}
	if err != nil {
		return errors.Wrap(err, "unable to find signer")
	}

	root, err := msg.Message.GetRoot()
	if err != nil {
		return errors.Wrap(err, "failed to get root")
	}

	pk, err := crypto.Ecrecover(root, msg.Signature)
	if err != nil {
		return errors.Wrap(err, "unable to recover public key")
	}

	addr := common.BytesToAddress(crypto.Keccak256(pk[1:])[12:])
	if addr != operator.ETHAddress {
		return errors.New("invalid signature")
	}
	return nil
}

func (fr *FROST) validateProtocolMessage(msg *ProtocolMsg) error {
	if msg.Round == Blame && msg.BlameMessage != nil {
		return nil
	}

	if msg.Round != fr.state.currentRound {
		return dkg.ErrMismatchRound{}
	}

	if valid := msg.validate(); !valid {
		return errors.New("invalid message")
	}
	return nil
}

func (fr *FROST) encryptByOperatorID(operatorID uint32, data []byte) ([]byte, error) {

	msg, ok := fr.state.msgs[Preparation][operatorID]
	if !ok {
		return nil, errors.New("no session pk found for the operator")
	}

	protocolMessage := &ProtocolMsg{}
	if err := protocolMessage.Decode(msg.Message.Data); err != nil {
		return nil, errors.Wrap(err, "failed to decode protocol msg")
	}

	sessionPK, err := ecies.NewPublicKeyFromBytes(protocolMessage.PreparationMessage.SessionPk)
	if err != nil {
		return nil, err
	}

	return ecies.Encrypt(sessionPK, data)
}

func (fr *FROST) toSignedMessage(msg *ProtocolMsg) (*dkg.SignedMessage, error) {

	msgBytes, err := msg.Encode()
	if err != nil {
		return nil, err
	}

	bcastMessage := &dkg.SignedMessage{
		Message: &dkg.Message{
			MsgType:    dkg.ProtocolMsgType,
			Identifier: fr.state.identifier,
			Data:       msgBytes,
		},
		Signer: fr.state.operatorID,
	}

	exist, operator, err := fr.storage.GetDKGOperator(fr.state.operatorID)
	if err != nil {
		return nil, err
	}
	if !exist {
		return nil, errors.Errorf("operator with id %d not found", fr.state.operatorID)
	}

	sig, err := fr.signer.SignDKGOutput(bcastMessage, operator.ETHAddress)
	if err != nil {
		return nil, err
	}
	bcastMessage.Signature = sig

	return bcastMessage, nil
}

func (fr *FROST) broadcastDKGMessage(msg *ProtocolMsg) error {
	bcastMessage, err := fr.toSignedMessage(msg)
	if err != nil {
		return err
	}

	if msg.Round == Blame {
		fr.state.msgs[Blame][uint32(fr.state.operatorID)] = bcastMessage
	} else {
		fr.state.msgs[fr.state.currentRound][uint32(fr.state.operatorID)] = bcastMessage
	}
	return fr.network.BroadcastDKGMessage(bcastMessage)
}
