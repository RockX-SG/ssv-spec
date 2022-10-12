package frost

import (
	crand "crypto/rand"
	"encoding/hex"
	"math/big"
	mrand "math/rand"
	"testing"

	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/dkg/frost"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

type FrostSpecTest struct {
	Name string

	RequestID       dkg.RequestID
	Threshold       uint64
	Operators       []types.OperatorID
	ExpectedOutcome struct {
		ValidatorPK     string
		Share           map[uint32]string
		OperatorPubKeys map[uint32]string
	}
	ExpectedError string
}

func (test *FrostSpecTest) TestName() string {
	return test.Name
}

func (test *FrostSpecTest) Run(t *testing.T) {

	outcomes := make(map[uint32]*dkg.KeyGenOutcome)

	err := func(t *testing.T) error {
		resetRandSeed()

		requestID := getRandRequestID()
		dkgsigner := testingutils.NewTestingKeyManager()
		storage := testingutils.NewTestingStorage()
		network := testingutils.NewTestingNetwork()

		kgps := make(map[types.OperatorID]dkg.KeyGenProtocol)
		for _, operatorID := range test.Operators {
			p := frost.New(network, operatorID, requestID, dkgsigner, storage)
			kgps[operatorID] = p
		}

		initMsg := &dkg.Init{
			OperatorIDs: test.Operators,
			Threshold:   uint16(test.Threshold),
		}

		for _, operatorID := range test.Operators {
			if err := kgps[operatorID].Start(initMsg); err != nil {
				return errors.Wrapf(err, "failed to start dkg protocol for operator %d", operatorID)
			}
		}

		for i := 0; i < 3; i++ {

			messages := network.BroadcastedMsgs
			network.BroadcastedMsgs = make([]*types.SSVMessage, 0)

			for _, msg := range messages {

				dkgMsg := &dkg.SignedMessage{}
				if err := dkgMsg.Decode(msg.Data); err != nil {
					return err
				}

				for _, operatorID := range test.Operators {
					if operatorID == dkgMsg.Signer {
						continue
					}

					finished, outcome, err := kgps[operatorID].ProcessMsg(dkgMsg)
					if err != nil {
						return err
					}

					if finished {
						outcomes[uint32(operatorID)] = outcome
					}
				}
			}
		}
		return nil
	}(t)

	if len(test.ExpectedError) > 0 {
		require.EqualError(t, err, test.ExpectedError)
	} else {
		require.NoError(t, err)
	}

	for _, operatorID := range test.Operators {

		outcome := outcomes[uint32(operatorID)].KeyGenOutput

		require.Equal(t, test.ExpectedOutcome.ValidatorPK, hex.EncodeToString(outcome.ValidatorPK))
		require.Equal(t, test.ExpectedOutcome.Share[uint32(operatorID)], outcome.Share.SerializeToHexStr())

		for opID, publicKey := range outcome.OperatorPubKeys {
			require.Equal(t, test.ExpectedOutcome.OperatorPubKeys[uint32(opID)], publicKey.SerializeToHexStr())
		}
	}

}

func resetRandSeed() {
	src := mrand.NewSource(1)
	src.Seed(12345)
	crand.Reader = mrand.New(src)
}

func getRandRequestID() dkg.RequestID {
	requestID := dkg.RequestID{}
	for i := range requestID {
		rndInt, _ := crand.Int(crand.Reader, big.NewInt(255))
		requestID[i] = rndInt.Bytes()[0]
	}
	return requestID
}
