package keygen

import (
	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/dkg/frost"
	"github.com/bloxapp/ssv-spec/dkg/spectest/tests"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
)

func InvalidNumberOfOperators() *tests.MsgProcessingSpecTest {
	ks := testingutils.TestingKeygenKeySet()
	network := testingutils.NewTestingNetwork()
	storage := testingutils.NewTestingStorage()
	keyManager := testingutils.NewTestingKeyManager()

	identifier := dkg.NewRequestID(ks.DKGOperators[1].ETHAddress, 1)

	// operators := make([]types.OperatorID, 0)
	// for i := 1; i <= 256; i++ {
	// 	operators = append(operators, types.OperatorID(i))
	// }

	init := testingutils.InitMessageData(
		[]types.OperatorID{1, 2, 3, 4, 5}, // number of operators should be 3f+1
		uint16(3),
		testingutils.TestingWithdrawalCredentials,
		testingutils.TestingForkVersion,
	)
	initBytes, _ := init.Encode()

	testingNode := dkg.NewNode(
		&dkg.Operator{
			OperatorID:       1,
			ETHAddress:       ks.DKGOperators[1].ETHAddress,
			EncryptionPubKey: &ks.DKGOperators[1].EncryptionKey.PublicKey,
		},
		&dkg.Config{
			KeygenProtocol:      frost.New,
			ReshareProtocol:     frost.NewResharing,
			Network:             network,
			Storage:             storage,
			SignatureDomainType: types.PrimusTestnet,
			Signer:              keyManager,
		},
	)

	return &tests.MsgProcessingSpecTest{
		Name:        "keygen/invalid-number-of-operators",
		TestingNode: testingNode,
		InputMessages: []*dkg.SignedMessage{
			testingutils.SignDKGMsg(ks.DKGOperators[1].SK, 1, &dkg.Message{
				MsgType:    dkg.InitMsgType,
				Identifier: identifier,
				Data:       initBytes,
			}),
		},
		OutputMessages: []*dkg.SignedMessage{},
		Output:         map[types.OperatorID]*dkg.SignedOutput{},
		KeySet:         ks,
		ExpectedError:  "could not start new dkg: init message invalid: invalid number of operators which has to be 3f+1",
	}
}
