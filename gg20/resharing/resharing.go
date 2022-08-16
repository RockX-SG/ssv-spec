package resharing

import (
	"github.com/bloxapp/ssv-spec/dkg/types"
	"github.com/bloxapp/ssv-spec/gg20/algorithms/vss"
	types2 "github.com/bloxapp/ssv-spec/gg20/types"
	"github.com/herumi/bls-eth-go-binary/bls"
	"sync"
)

type Round = uint8

func init() {
	_ = bls.Init(bls.BLS12_381)
	_ = bls.SetETHmode(bls.EthModeDraft07)
}

type Resharing struct {
	SessionID         []byte
	Round             Round
	OldCommittee      []uint64
	NewCommittee      []uint64
	Coefficients      vss.Coefficients
	BlindFactor       [32]byte // A random number
	DlogR             *bls.Fr
	PartyI            uint64
	PartyCount        uint64
	skI               *bls.SecretKey
	Round1Msgs        map[uint64]*types2.ParsedRsMessage
	Round2Msgs        map[uint64]*types2.ParsedRsMessage
	Round3Msgs        map[uint64]*types2.ParsedRsMessage
	Round4Msgs        map[uint64]*types2.ParsedRsMessage
	Round5Msgs        map[uint64]*types2.ParsedRsMessage
	Outgoing          types2.ParsedMessages
	Output            *types.LocalKeyShare
	HandleMessageType int32
	ownShare          *bls.Fr
	inMutex           sync.Mutex
	outMutex          sync.Mutex
}
