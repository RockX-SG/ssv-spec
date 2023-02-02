package keygen

import (
	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/dkg/frost"
	"github.com/bloxapp/ssv-spec/dkg/spectest/tests"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
)

func MismatchRequestID() *tests.MsgProcessingSpecTest {
	ks := testingutils.TestingKeygenKeySet()
	network := testingutils.NewTestingNetwork()
	storage := testingutils.NewTestingStorage()
	keyManager := testingutils.NewTestingKeyManager()

	identifier := dkg.NewRequestID(ks.DKGOperators[1].ETHAddress, 1)
	anotherID := testingutils.GetRandRequestID()

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

	// Start a keygen with anotherID
	initSignedMsg := testingutils.SignDKGMsg(ks.DKGOperators[1].SK, 1, &dkg.Message{
		MsgType:    dkg.InitMsgType,
		Identifier: anotherID,
		Data:       initBytes,
	})
	initSignedMsgBytes, _ := initSignedMsg.Encode()

	testingNode.ProcessMessage(&types.SSVMessage{
		MsgType: types.DKGMsgType,
		Data:    initSignedMsgBytes,
	})

	_ = frost.Testing_PreparationMessage(2, testingutils.KeygenMsgStore)

	return &tests.MsgProcessingSpecTest{
		Name:        "keygen/mismatch-request-id",
		TestingNode: testingNode,
		InputMessages: []*dkg.SignedMessage{
			testingutils.SignDKGMsg(ks.DKGOperators[1].SK, 1, &dkg.Message{
				MsgType:    dkg.InitMsgType,
				Identifier: identifier,
				Data:       initBytes,
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[2].SK, 2, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: anotherID,
				// Data:       ,
			}),
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
		ExpectedError: "could not find dkg runner",
	}
}
