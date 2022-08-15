package keygen

import "C"
import (
	"bytes"
	"crypto"
	_ "crypto/sha256"
	"errors"
	"fmt"
	"github.com/bloxapp/ssv-spec/dkg/types"
	"github.com/bloxapp/ssv-spec/gg20"
	"github.com/bloxapp/ssv-spec/gg20/algorithms/vss"
	types2 "github.com/bloxapp/ssv-spec/gg20/types"
	"github.com/herumi/bls-eth-go-binary/bls"
	log "github.com/sirupsen/logrus"
	"sync"
)

type Round = uint8

const (
	SECURITY = 256
)

var (
	ErrInvalidRound  = errors.New("invalid round")
	ErrExpectMessage = errors.New("expected message not found")
)

func init() {
	_ = bls.Init(bls.BLS12_381)
	_ = bls.SetETHmode(bls.EthModeDraft07)
}

type Keygen struct {
	SessionID         []byte
	Round             Round
	Committee         []uint64
	Coefficients      vss.Coefficients
	BlindFactor       [32]byte // A random number
	DlogR             *bls.Fr
	PartyI            uint64
	PartyCount        uint64
	skI               *bls.SecretKey
	Round1Msgs        map[uint64]*types2.ParsedKGMessage
	Round2Msgs        map[uint64]*types2.ParsedKGMessage
	Round3Msgs        map[uint64]*types2.ParsedKGMessage
	Round4Msgs        map[uint64]*types2.ParsedKGMessage
	Outgoing          types2.ParsedMessages
	Output            *types.LocalKeyShare
	HandleMessageType int32
	ownShare          *bls.Fr
	inMutex           sync.Mutex
	outMutex          sync.Mutex
}

func EmptyKeygen(t, n uint64) Keygen {
	return Keygen{
		SessionID:         []byte{},
		Round:             0,
		Committee:         nil,
		Coefficients:      make(vss.Coefficients, t+1),
		BlindFactor:       [32]byte{},
		DlogR:             new(bls.Fr),
		PartyI:            0,
		PartyCount:        n,
		skI:               nil,
		Round1Msgs:        make(map[uint64]*types2.ParsedKGMessage, n),
		Round2Msgs:        make(map[uint64]*types2.ParsedKGMessage, n),
		Round3Msgs:        make(map[uint64]*types2.ParsedKGMessage, n),
		Round4Msgs:        make(map[uint64]*types2.ParsedKGMessage, n),
		Outgoing:          nil,
		Output:            nil,
		HandleMessageType: int32(types.ProtocolMsgType),
		ownShare:          nil,
		inMutex:           sync.Mutex{},
		outMutex:          sync.Mutex{},
	}
}

func NewKeygen(sessionId []byte, i, t uint64, committee []uint64) (*Keygen, error) {
	err := checkIndexes(committee)
	if err != nil {
		return nil, err
	}
	kg := EmptyKeygen(t, uint64(len(committee)))
	kg.Committee = committee
	kg.SessionID = sessionId
	kg.PartyI = i
	kg.Coefficients = vss.CreatePolynomial(int(t + 1))
	copy(kg.BlindFactor[:], gg20.MustGetRandomInt(SECURITY).Bytes())
	kg.DlogR.SetByCSPRNG()
	return &kg, nil
}

func (k *Keygen) Proceed() error {

	k.inMutex.Lock()
	defer k.inMutex.Unlock()
	var err error
	switch k.Round {
	case 0:
		if err = k.r0CanProceed(); err == nil {
			if err = k.r0Proceed(); err != nil {
				return err
			}
		}
	case 1:
		if err = k.r1CanProceed(); err == nil {
			if err = k.r1Proceed(); err != nil {
				return err
			}
		}
	case 2:
		if err = k.r2CanProceed(); err == nil {
			if err = k.r2Proceed(); err != nil {
				return err
			}
		}
	case 3:
		if err = k.r3CanProceed(); err == nil {
			if err = k.r3Proceed(); err != nil {
				return err
			}
		}
	case 4:
		if err = k.r4CanProceed(); err == nil {
			if err = k.r4Proceed(); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid round of State machine: %d", k.Round)
	}
	return err
}

func checkIndexes(committee []uint64) error {
	visited := make(map[uint64]struct{})
	for _, v := range committee {
		if v == 0 {
			return errors.New("party index should not be 0")
		}
		if _, ok := visited[v]; ok {
			return fmt.Errorf("duplicate indexes %d", v)
		}
		visited[v] = struct{}{}
	}
	return nil
}

func (k *Keygen) ValidSender(sender uint64) bool {
	for _, u := range k.Committee {
		if u == sender {
			return true
		}
	}
	return false
}

func (k *Keygen) PushMessage(msg *types2.ParsedKGMessage) error {
	if msg == nil || !msg.IsValid() {
		return errors.New("invalid message")
	}
	if !k.ValidSender(msg.Header.Sender) {
		return errors.New("invalid sender")
	}
	rn, err := msg.GetRoundNumber()
	if err != nil {
		return err
	}
	k.inMutex.Lock()
	defer k.inMutex.Unlock()
	switch rn {
	case 1:
		k.Round1Msgs[msg.Header.Sender] = msg
		return nil
	case 2:
		k.Round2Msgs[msg.Header.Sender] = msg
		return nil
	case 3:
		k.Round3Msgs[msg.Header.Sender] = msg
		return nil
	case 4:
		k.Round4Msgs[msg.Header.Sender] = msg
		return nil
	}
	return errors.New("unable to handle message")

}

func (k *Keygen) GetOutgoing() (types2.ParsedMessages, error) {
	if success := k.outMutex.TryLock(); success {
		defer k.outMutex.Unlock()
		out := k.Outgoing[:]
		if len(out) > 0 {
			k.trace(fmt.Sprintf("outgoing has %d items", len(out)))
		}
		k.Outgoing = nil
		return out, nil
	} else {
		return nil, errors.New("failed to acquire lock, try again later")
	}
}

func (k *Keygen) pushOutgoing(msg *types2.ParsedKGMessage) {
	k.outMutex.Lock()
	defer k.outMutex.Unlock()
	k.Outgoing = append(k.Outgoing, msg)
}

func (k *Keygen) GetDecommitment() [][]byte {
	decomm := make([][]byte, len(k.Coefficients))
	for i, coefficient := range k.Coefficients {
		decomm[i] = bls.CastToSecretKey(&coefficient).GetPublicKey().Serialize()
	}
	return decomm
}

func (k *Keygen) GetCommitment() []byte {

	var data []byte
	decomm := k.GetDecommitment()
	data = append(data, gg20.Uint64ToBytes(k.PartyI)...)
	data = append(data, k.BlindFactor[:]...)
	for _, bytes := range decomm {
		data = append(data, bytes...)
	}
	hash := crypto.SHA256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

func (k *Keygen) VerifyCommitment(r1 types2.KGRound1Msg, r2 types2.KGRound2Msg, partyI uint64) bool {
	if len(k.Coefficients) != len(r2.Decommitment) {
		return false
	}
	var data []byte
	data = append(data, gg20.Uint64ToBytes(partyI)...)
	data = append(data, r2.BlindFactor...)
	for _, bytes := range r2.Decommitment {
		data = append(data, bytes...)
	}
	hash := crypto.SHA256.New()
	hash.Write(data)
	comm := hash.Sum(nil)
	return bytes.Compare(r1.Commitment, comm) == 0
}

func (k *Keygen) trace(msg interface{}) {
	log.WithFields(log.Fields{
		"participant": k.PartyI,
	}).Trace(msg)
}
