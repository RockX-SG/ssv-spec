package keygen

import (
	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/dkg/frost"
	"github.com/bloxapp/ssv-spec/dkg/spectest/tests"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
)

func InvalidOperatorID() *tests.MsgProcessingSpecTest {
	ks := testingutils.TestingKeygenKeySet()
	network := testingutils.NewTestingNetwork()
	storage := testingutils.NewTestingStorage()
	keyManager := testingutils.NewTestingKeyManager()

	identifier := dkg.NewRequestID(ks.DKGOperators[1].ETHAddress, 1)

	invalidOperatorID := types.OperatorID(999) // operators in this keygen are 1, 2, 3, 4
	ks2 := testingutils.Testing7SharesSet()

	init := testingutils.InitMessageData(
		[]types.OperatorID{1, 2, 3, 4},
		uint16(ks.Threshold),
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

	invalidMsg := testingutils.SignDKGMsg(ks2.DKGOperators[2].SK, invalidOperatorID, &dkg.Message{
		MsgType:    dkg.ProtocolMsgType,
		Identifier: identifier,
		Data:       frost.Testing_PreparationMessageBytes(2, testingutils.ResharingMsgStore),
	})
	invalidMsg.Signer = invalidOperatorID

	return &tests.MsgProcessingSpecTest{
		Name:        "keygen/invalid-operator-id",
		TestingNode: testingNode,
		InputMessages: []*dkg.SignedMessage{
			testingutils.SignDKGMsg(ks.DKGOperators[1].SK, 1, &dkg.Message{
				MsgType:    dkg.InitMsgType,
				Identifier: identifier,
				Data:       initBytes,
			}),
			invalidMsg,
		},
		OutputMessages: []*dkg.SignedMessage{
			testingutils.SignDKGMsg(ks.DKGOperators[1].SK, 1, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_PreparationMessageBytes(1, testingutils.KeygenMsgStore),
			}),
		},
		Output:        map[types.OperatorID]*dkg.SignedOutput{},
		KeySet:        ks,
		ExpectedError: "dkg msg not valid: can't find operator",
	}
}
