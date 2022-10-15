package frost

import (
	"encoding/hex"
	"testing"

	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/dkg/frost"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
	"github.com/herumi/bls-eth-go-binary/bls"
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
		require.Equal(t, test.ExpectedOutcome.OperatorPubKeys[uint32(operatorID)], outcome.OperatorPubKeys[operatorID].SerializeToHexStr())
	}

}

func TestingFrost(threshold uint64, operators, operatorsOld []types.OperatorID, isResharing bool, oldKeygenOutcomes *testingutils.TestKeygenOutcome) (map[uint32]*dkg.KeyGenOutcome, error) {

	testingutils.ResetRandSeed()
	requestID := testingutils.GetRandRequestID()
	dkgsigner := testingutils.NewTestingKeyManager()
	storage := testingutils.NewTestingStorage()
	network := testingutils.NewTestingNetwork()

	nodes := make(map[types.OperatorID]*dkg.Node)

	for _, operatorID := range operators {

		_, operator, _ := storage.GetDKGOperator(operatorID)
		p := frost.New(network, operatorID, requestID, dkgsigner, storage)

		node := dkg.NewNode(
			operator,
			&dkg.Config{
				Protocol: func(network dkg.Network, operatorID types.OperatorID, identifier dkg.RequestID) dkg.KeyGenProtocol {
					return p
				},
				Network: network,
				Storage: storage,
				Signer:  dkgsigner,
			})
		nodes[operatorID] = node
	}

	if isResharing {

		operatorsOldList := types.OperatorList(operatorsOld).ToUint32List()
		keygenOutcomeOld := oldKeygenOutcomes.ToKeygenOutcomeMap(threshold, operatorsOldList)

		for _, operatorID := range operatorsOld {

			_, operator, _ := storage.GetDKGOperator(operatorID)
			p := frost.NewResharing(network, operatorID, requestID, dkgsigner, storage, keygenOutcomeOld[uint32(operatorID)], operatorsOldList[:threshold+1])

			node := dkg.NewNode(
				operator,
				&dkg.Config{
					Protocol: func(network dkg.Network, operatorID types.OperatorID, identifier dkg.RequestID) dkg.KeyGenProtocol {
						return p
					},
					Network: network,
					Storage: storage,
					Signer:  dkgsigner,
				})
			nodes[operatorID] = node
		}

		for _, operatorID := range operators {

			_, operator, _ := storage.GetDKGOperator(operatorID)
			p := frost.NewResharing(network, operatorID, requestID, dkgsigner, storage, nil, operatorsOldList[:threshold+1])

			node := dkg.NewNode(
				operator,
				&dkg.Config{
					Protocol: func(network dkg.Network, operatorID types.OperatorID, identifier dkg.RequestID) dkg.KeyGenProtocol {
						return p
					},
					Network: network,
					Storage: storage,
					Signer:  dkgsigner,
				})
			nodes[operatorID] = node
		}
	}

	alloperators := operators
	if isResharing {
		alloperators = append(alloperators, operatorsOld...)
	}

	initMsg := &dkg.Init{
		OperatorIDs:           operators,
		Threshold:             uint16(threshold),
		WithdrawalCredentials: testingutils.TestingWithdrawalCredentials,
		Fork:                  testingutils.TestingForkVersion,
	}
	initMsgBytes, _ := initMsg.Encode()

	for _, operatorID := range alloperators {

		initSignedMessage, _ := toSignedMessage(
			requestID,
			operatorID,
			dkg.InitMsgType,
			initMsgBytes,
			storage,
			dkgsigner,
		)
		initSignedMessageBytes, _ := initSignedMessage.Encode()

		startMessage := &types.SSVMessage{
			MsgType: types.DKGMsgType,
			Data:    initSignedMessageBytes,
		}
		if err := nodes[operatorID].ProcessMessage(startMessage); err != nil {
			return nil, errors.Wrapf(err, "failed to start dkg protocol for operator %d", operatorID)
		}
	}

	for round := 1; round <= 5; round++ {

		messages := network.BroadcastedMsgs
		network.BroadcastedMsgs = make([]*types.SSVMessage, 0)

		for _, msg := range messages {

			dkgMsg := &dkg.SignedMessage{}
			if err := dkgMsg.Decode(msg.Data); err != nil {
				return nil, err
			}

			operatorList := alloperators
			if isResharing && round > 2 {
				operatorList = operators
			}

			for _, operatorID := range operatorList {

				if operatorID == dkgMsg.Signer {
					continue
				}
				if err := nodes[operatorID].ProcessMessage(msg); err != nil {
					return nil, err
				}
			}
		}
	}

	ks := testingutils.Testing13SharesSet()
	ret := make(map[uint32]*dkg.KeyGenOutcome)
	outputs := network.DKGOutputs

	for operatorID, output := range outputs {
		pk := &bls.PublicKey{}
		pk.Deserialize(output.Data.SharePubKey)

		share, _ := dkgsigner.Decrypt(ks.DKGOperators[operatorID].EncryptionKey, output.Data.EncryptedShare)
		sk := &bls.SecretKey{}
		sk.Deserialize(share)

		ret[uint32(operatorID)] = &dkg.KeyGenOutcome{
			KeyGenOutput: &dkg.KeyGenOutput{
				ValidatorPK: output.Data.ValidatorPubKey,
				Share:       sk,
				OperatorPubKeys: map[types.OperatorID]*bls.PublicKey{
					operatorID: pk,
				},
				Threshold: threshold,
			},
		}
	}

	return ret, nil
}

func toSignedMessage(requestID dkg.RequestID, id types.OperatorID, msgType dkg.MsgType, data []byte, storage dkg.Storage, signer types.DKGSigner) (*dkg.SignedMessage, error) {

	signedMessage := &dkg.SignedMessage{
		Message: &dkg.Message{
			MsgType:    msgType,
			Identifier: requestID,
			Data:       data,
		},
		Signer: id,
	}

	exist, operator, err := storage.GetDKGOperator(id)
	if err != nil {
		return nil, err
	}
	if !exist {
		return nil, errors.Errorf("operator with id %d not found", id)
	}

	sig, err := signer.SignDKGOutput(signedMessage, operator.ETHAddress)
	if err != nil {
		return nil, err
	}
	signedMessage.Signature = sig

	return signedMessage, nil
}
