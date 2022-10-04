package frost

import (
	"math/rand"

	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/dkg/frost"
	ecies "github.com/ecies/go/v2"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
)

var thisCurve = curves.BLS12381G1()

func init() {
	types.InitBLS()
}

type FROST struct {
	identifier   dkg.RequestID
	network      dkg.Network
	signer       types.DKGSigner
	storage      dkg.Storage
	threshold    uint32
	currentRound DKGRound

	operatorID   types.OperatorID
	operators    []uint32
	operatorsOld []uint32
	participant  *frost.DkgParticipant
	sessionSK    *ecies.PrivateKey

	msgs map[DKGRound]map[uint32]*dkg.SignedMessage

	oldKeyGenOutput *dkg.KeyGenOutput
	operatorShares  map[uint32]*bls.SecretKey
}

type DKGRound int

const (
	Uninitialized DKGRound = iota
	Join                   // Used for old committee to join, otherwise the protocol can't proceed
	Preparation
	Round1
	Round2
	Blame
)

func New(
	network dkg.Network,
	operatorID types.OperatorID,
	requestID dkg.RequestID,
	signer types.DKGSigner,
	storage dkg.Storage,
) dkg.KeyGenProtocol {

	msgs := make(map[DKGRound]map[uint32]*dkg.SignedMessage)
	msgs[Preparation] = make(map[uint32]*dkg.SignedMessage)
	msgs[Round1] = make(map[uint32]*dkg.SignedMessage)
	msgs[Round2] = make(map[uint32]*dkg.SignedMessage)
	msgs[Blame] = make(map[uint32]*dkg.SignedMessage)

	return &FROST{
		identifier:   requestID,
		network:      network,
		signer:       signer,
		storage:      storage,
		operatorID:   operatorID,
		currentRound: Uninitialized,

		msgs:           msgs,
		operatorShares: make(map[uint32]*bls.SecretKey),
	}
}

func NewResharing(
	network dkg.Network,
	operatorID types.OperatorID,
	requestID dkg.RequestID,
	signer types.DKGSigner,
	storage dkg.Storage,
	oldKeyGenOutput dkg.KeyGenOutput,
) dkg.KeyGenProtocol {

	msgs := make(map[DKGRound]map[uint32]*dkg.SignedMessage)
	msgs[Preparation] = make(map[uint32]*dkg.SignedMessage)
	msgs[Round1] = make(map[uint32]*dkg.SignedMessage)
	msgs[Round2] = make(map[uint32]*dkg.SignedMessage)
	msgs[Blame] = make(map[uint32]*dkg.SignedMessage)

	return &FROST{
		identifier: requestID,
		network:    network,
		signer:     signer,
		storage:    storage,
		operatorID: operatorID,

		msgs:            msgs,
		operatorShares:  make(map[uint32]*bls.SecretKey),
		oldKeyGenOutput: &oldKeyGenOutput,
	}
}

func (fr *FROST) Start(init *dkg.Init) error {

	// TODO: Move Init/Reshare to New instead of in Start
	// TODO: If Reshare, check threshold

	otherOperators := make([]uint32, 0)
	for _, operatorID := range init.OperatorIDs {
		if fr.operatorID == operatorID {
			continue
		}
		otherOperators = append(otherOperators, uint32(operatorID))
	}

	operators := []uint32{uint32(fr.operatorID)}
	operators = append(operators, otherOperators...)
	fr.operators = operators

	ctx := make([]byte, 16)
	if _, err := rand.Read(ctx); err != nil {
		return err
	}

	participant, err := frost.NewDkgParticipant(uint32(fr.operatorID), uint32(len(operators)), string(ctx), thisCurve, otherOperators...)
	if err != nil {
		return errors.Wrap(err, "failed to initialize a dkg participant")
	}

	fr.participant = participant
	fr.threshold = uint32(init.Threshold)

	k, err := ecies.GenerateKey()
	if err != nil {
		return errors.Wrap(err, "failed to generate session sk")
	}
	fr.sessionSK = k

	// TODO: If resharing, go to Join state instead of Preparation state
	fr.currentRound = Preparation
	msg := &ProtocolMsg{
		Round: Preparation,
		PreparationMessage: &PreparationMessage{
			SessionPk: k.PublicKey.Bytes(true),
		},
	}
	return fr.broadcastDKGMessage(msg)
}

func (fr *FROST) ProcessMsg(msg *dkg.SignedMessage) (bool, *dkg.KeyGenOutput, error) {

	if err := msg.Validate(); err != nil {
		return false, nil, errors.Wrap(err, "failed to validate message signature")
	}

	protocolMessage := &ProtocolMsg{}
	if err := protocolMessage.Decode(msg.Message.Data); err != nil {
		return false, nil, errors.Wrap(err, "failed to decode protocol msg")
	}

	if valid := protocolMessage.validate(); !valid {
		return false, nil, errors.New("failed to validate protocol message")
	}

	if fr.msgs[protocolMessage.Round] == nil {
		fr.msgs[protocolMessage.Round] = make(map[uint32]*dkg.SignedMessage)
	}

	originalMessage, ok := fr.msgs[protocolMessage.Round][uint32(msg.Signer)]
	if ok {
		return false, nil, fr.createBlameTypeInconsistentMessageRequest(originalMessage, msg)
	}

	fr.msgs[protocolMessage.Round][uint32(msg.Signer)] = msg

	switch protocolMessage.Round {
	case Preparation:
		// Received all
		if fr.canProceedThisRound(Round1) {
			if err := fr.processRound1(); err != nil {
				return false, nil, err
			}
		}
	case Round1:
		if fr.canProceedThisRound(Round2) {
			if err := fr.processRound2(); err != nil {
				return false, nil, err
			}
		}
	case Round2:
		if fr.canProceedThisRound(-1) { // -1 checks if protocol has finished with round 2
			out, err := fr.processKeygenOutput()
			if err != nil {
				return false, nil, err
			}
			return true, out, nil
		}
	case Blame:
		out, err := fr.processBlame()
		if err != nil {
			return false, nil, err
		}
		return true, &dkg.KeyGenOutput{BlameOutout: out}, err
	default:
		return true, nil, dkg.ErrInvalidRound{}
	}

	return false, nil, nil
}

func (fr *FROST) canProceedThisRound(round DKGRound) bool {

	// Join (O) -> Preparation (N) -> Round1 (N) -> Round2 (O)
	switch fr.currentRound {
	case Join:
		return fr.allMessagesReceivedFor(Join, fr.operatorsOld)
	case Preparation:
		return fr.allMessagesReceivedFor(Preparation, fr.operators)
	case Round1:
		return fr.allMessagesReceivedFor(Round1, fr.operators)
	case Round2:
		if fr.isResharing() {
			fr.allMessagesReceivedFor(Round2, fr.operatorsOld)
		} else {
			fr.allMessagesReceivedFor(Round2, fr.operators)
		}
	}
	return true
}

func (fr *FROST) allMessagesReceivedFor(round DKGRound, operators []uint32) bool {
	for _, operatorID := range operators {
		if _, ok := fr.msgs[round][operatorID]; !ok {
			return false
		}
	}
	return true
}

func (fr *FROST) isResharing() bool {
	return len(fr.operatorsOld) > 0
}

func (fr *FROST) inOldCommittee() bool {
	for _, id := range fr.operatorsOld {
		if types.OperatorID(id) == fr.operatorID {
			return true
		}
	}
	return false
}

func (fr *FROST) inNewCommittee() bool {
	for _, id := range fr.operators {
		if types.OperatorID(id) == fr.operatorID {
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
	default:
		return false
	}
}

func (fr *FROST) encryptByOperatorID(operatorID uint32, data []byte) ([]byte, error) {

	msg, ok := fr.msgs[Preparation][operatorID]
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
			Identifier: fr.identifier,
			Data:       msgBytes,
		},
		Signer: fr.operatorID,
	}

	exist, operator, err := fr.storage.GetDKGOperator(fr.operatorID)
	if err != nil {
		return nil, err
	}
	if !exist {
		return nil, errors.Errorf("operator with id %d not found", fr.operatorID)
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

	fr.msgs[fr.currentRound][uint32(fr.operatorID)] = bcastMessage
	return fr.network.BroadcastDKGMessage(bcastMessage)
}
