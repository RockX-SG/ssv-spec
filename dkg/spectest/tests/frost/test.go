package frost

import (
	"encoding/hex"
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

	// Keygen Options
	Threshold uint64
	Operators []types.OperatorID

	// Resharing Options
	IsResharing       bool
	OperatorsOld      []types.OperatorID
	OldKeygenOutcomes *testingutils.TestKeygenOutcome

	// Expected
	ExpectedOutcome testingutils.TestKeygenOutcome
	ExpectedError   string
}

func (test *FrostSpecTest) TestName() string {
	return test.Name
}

func (test *FrostSpecTest) Run(t *testing.T) {

	outcomes, err := TestingFrost(
		test.Threshold,
		test.Operators,
		test.OperatorsOld,
		test.IsResharing,
		test.OldKeygenOutcomes,
	)

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

func TestingFrost(threshold uint64, operators, operatorsOld []types.OperatorID, isResharing bool, oldKeygenOutcomes *testingutils.TestKeygenOutcome) (map[uint32]*dkg.KeyGenOutcome, error) {

	testingutils.ResetRandSeed()

	requestID := testingutils.GetRandRequestID()
	dkgsigner := testingutils.NewTestingKeyManager()
	storage := testingutils.NewTestingStorage()
	network := testingutils.NewTestingNetwork()

	kgps := make(map[types.OperatorID]dkg.KeyGenProtocol)
	for _, operatorID := range operators {
		p := frost.New(network, operatorID, requestID, dkgsigner, storage)
		kgps[operatorID] = p
	}

	if isResharing {
		operatorsOldList := types.OperatorList(operatorsOld).ToUint32List()
		keygenOutcomeOld := oldKeygenOutcomes.ToKeygenOutcomeMap(threshold, operatorsOldList)

		for _, operatorID := range operatorsOld {
			p := frost.NewResharing(network, operatorID, requestID, dkgsigner, storage, keygenOutcomeOld[uint32(operatorID)], operatorsOldList[:threshold+1])
			kgps[operatorID] = p

		}

		for _, operatorID := range operators {
			p := frost.NewResharing(network, operatorID, requestID, dkgsigner, storage, nil, operatorsOldList[:threshold+1])
			kgps[operatorID] = p
		}
	}

	alloperators := operators
	if isResharing {
		alloperators = append(alloperators, operatorsOld...)
	}

	initMsg := &dkg.Init{
		OperatorIDs: operators,
		Threshold:   uint16(threshold),
	}

	for _, operatorID := range alloperators {
		if err := kgps[operatorID].Start(initMsg); err != nil {
			return nil, errors.Wrapf(err, "failed to start dkg protocol for operator %d", operatorID)
		}
	}

	outcomes := make(map[uint32]*dkg.KeyGenOutcome)
	for i := 0; i < 3; i++ {

		messages := network.BroadcastedMsgs
		network.BroadcastedMsgs = make([]*types.SSVMessage, 0)

		for _, msg := range messages {

			dkgMsg := &dkg.SignedMessage{}
			if err := dkgMsg.Decode(msg.Data); err != nil {
				return nil, err
			}

			for _, operatorID := range alloperators {

				if operatorID == dkgMsg.Signer {
					continue
				}

				finished, outcome, err := kgps[operatorID].ProcessMsg(dkgMsg)
				if err != nil {
					return nil, err
				}
				if finished {
					outcomes[uint32(operatorID)] = outcome
				}
			}
		}
	}

	return outcomes, nil
}
