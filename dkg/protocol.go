package dkg

import (
	"github.com/bloxapp/ssv-spec/types"
	"github.com/herumi/bls-eth-go-binary/bls"
)

// ProtocolOutput is the bare minimum output from the protocol
type ProtocolOutput struct {
	Share           *bls.SecretKey
	OperatorIDs     []types.OperatorID
	OperatorPubKeys []bls.PublicKey
	ValidatorPK     types.ValidatorPK
}

// Protocol is an interface for all DKG protocol to support a variety of protocols for future upgrades
type Protocol interface {
	Start(init *Init) ([]Message, error)
	// ProcessMsg returns true and a bls share if finished
	ProcessMsg(msg *Message) ([]Message, error)
}
