package blame

import (
	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/dkg/frost"
	"github.com/bloxapp/ssv-spec/dkg/spectest/tests"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
)

func BlameTypeInvalidScalar_HappyFlow() *tests.MsgProcessingSpecTest {
	ks := testingutils.TestingKeygenKeySet()
	network := testingutils.NewTestingNetwork()
	storage := testingutils.NewTestingStorage()
	keyManager := testingutils.NewTestingKeyManager()

	identifier := dkg.NewRequestID(ks.DKGOperators[1].ETHAddress, 1)
	initBytes := testingutils.InitMessageDataBytes(
		[]types.OperatorID{1, 2, 3, 4},
		uint16(ks.Threshold),
		testingutils.TestingWithdrawalCredentials,
		testingutils.TestingForkVersion,
	)

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
		Name:        "blame/invalid scalar/happy flow",
		TestingNode: testingNode,
		InputMessages: []*dkg.SignedMessage{
			testingutils.SignDKGMsg(ks.DKGOperators[1].SK, 1, &dkg.Message{
				MsgType:    dkg.InitMsgType,
				Identifier: identifier,
				Data:       initBytes,
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[2].SK, 2, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_PreparationMessageBytes(2, testingutils.KeygenMsgStore),
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[3].SK, 3, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_PreparationMessageBytes(3, testingutils.KeygenMsgStore),
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[4].SK, 4, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_PreparationMessageBytes(4, testingutils.KeygenMsgStore),
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[2].SK, 2, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       makeInvalidForInvalidScalar(frost.Testing_Round1MessageBytes(2, testingutils.KeygenMsgStore)),
			}),
		},
		OutputMessages: []*dkg.SignedMessage{
			testingutils.SignDKGMsg(ks.DKGOperators[1].SK, 1, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_PreparationMessageBytes(1, testingutils.KeygenMsgStore),
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[1].SK, 1, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_Round1MessageBytes(1, testingutils.KeygenMsgStore),
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[1].SK, 1, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data: frost.Testing_BlameMessageBytes(2, frost.InvalidMessage, []*dkg.SignedMessage{
					testingutils.SignDKGMsg(ks.DKGOperators[2].SK, 2, &dkg.Message{
						MsgType:    dkg.ProtocolMsgType,
						Identifier: identifier,
						Data:       makeInvalidForInvalidScalar(frost.Testing_Round1MessageBytes(2, testingutils.KeygenMsgStore)),
					}),
				}),
			}),
		},
		Output:        map[types.OperatorID]*dkg.SignedOutput{},
		KeySet:        ks,
		ExpectedError: "",
	}
}
