package dkg

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/bloxapp/ssv-spec/types"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
)

type ProtocolOutcome struct {
	ProtocolOutput *KeyGenOutput
	KeySignOutput  *KeySignOutput
	BlameOutput    *BlameOutput
}

func (o *ProtocolOutcome) IsFinishedWithKeygen() bool {
	return o.ProtocolOutput != nil
}

func (o *ProtocolOutcome) IsFinishedWithKeySign() bool {
	return o.KeySignOutput != nil
}

func (o *ProtocolOutcome) IsFailedWithBlame() bool {
	return o.BlameOutput != nil
}

func (o *ProtocolOutcome) isValid() bool {
	a := o.ProtocolOutput
	b := o.KeySignOutput
	c := o.BlameOutput
	hasA := a != nil && b == nil && c == nil
	hasB := a == nil && b != nil && c == nil
	hasC := a == nil && b == nil && c != nil
	return hasA || hasB || hasC
}

// KeyGenOutput is the bare minimum output from the protocol
type KeyGenOutput struct {
	Share           *bls.SecretKey
	OperatorPubKeys map[types.OperatorID]*bls.PublicKey
	ValidatorPK     types.ValidatorPK
	Threshold       uint64
}

// KeySignOutput is the output of signature protocol
type KeySignOutput struct {
	RequestID   RequestID
	Signature   []byte
	ValidatorPK types.ValidatorPK
}

func (o *KeySignOutput) Encode() ([]byte, error) {
	return json.Marshal(o)
}

func (o *KeySignOutput) Decode(data []byte) error {
	return json.Unmarshal(data, o)
}

func (o *KeySignOutput) GetRoot() ([32]byte, error) {
	marshaledRoot, err := o.Encode()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "could not encode Message")
	}
	return sha256.Sum256(marshaledRoot), nil
}

// BlameOutput is the output of blame round
type BlameOutput struct {
	Valid        bool
	BlameMessage *SignedMessage
}

// Protocol is an interface for all DKG protocol to support a variety of protocols for future upgrades
type Protocol interface {
	Start() error
	// ProcessMsg returns true and a bls share if finished
	ProcessMsg(msg *SignedMessage) (bool, *ProtocolOutcome, error)
}
