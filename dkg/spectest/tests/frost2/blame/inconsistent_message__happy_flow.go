package blame

import (
	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/dkg/frost"
	"github.com/bloxapp/ssv-spec/dkg/frost/frostutils"
	"github.com/bloxapp/ssv-spec/dkg/spectest/tests/frost2"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
)

func BlameTypeInconsistentMessage_HappyFlow() *frost2.MsgProcessingSpecTest {
	ks := testingutils.Testing4SharesSet()
	network := testingutils.NewTestingNetwork()
	storage := testingutils.NewTestingStorage()
	keyManager := testingutils.NewTestingKeyManager()

	identifier := dkg.NewRequestID(ks.DKGOperators[1].ETHAddress, 1)
	init := &dkg.Init{
		OperatorIDs:           []types.OperatorID{1, 2, 3, 4},
		Threshold:             3,
		WithdrawalCredentials: testingutils.TestingWithdrawalCredentials,
		Fork:                  testingutils.TestingForkVersion,
	}
	initBytes, _ := init.Encode()

	return &frost2.MsgProcessingSpecTest{
		Name: "blame/inconsistent message/happy flow",
		Operator: &dkg.Operator{
			OperatorID:       1,
			ETHAddress:       ks.DKGOperators[1].ETHAddress,
			EncryptionPubKey: &ks.DKGOperators[1].EncryptionKey.PublicKey,
		},
		Network: network,
		Signer:  keyManager,
		Storage: storage,
		InputMessages: []*dkg.SignedMessage{
			testingutils.SignDKGMsg2(ks.DKGOperators[1].SK, 1, &dkg.Message{
				MsgType:    dkg.InitMsgType,
				Identifier: identifier,
				Data:       initBytes,
			}),
			testingutils.SignDKGMsg2(ks.DKGOperators[2].SK, 2, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frostutils.KeygenMsgStore.PreparationMessageBytes(2),
			}),
			testingutils.SignDKGMsg2(ks.DKGOperators[3].SK, 3, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frostutils.KeygenMsgStore.PreparationMessageBytes(3),
			}),
			testingutils.SignDKGMsg2(ks.DKGOperators[4].SK, 4, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frostutils.KeygenMsgStore.PreparationMessageBytes(4),
			}),
			testingutils.SignDKGMsg2(ks.DKGOperators[2].SK, 2, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frostutils.KeygenMsgStore.Round1MessageBytes(2),
			}),
			testingutils.SignDKGMsg2(ks.DKGOperators[2].SK, 2, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       makeInvalidForInconsistentMessage(frostutils.KeygenMsgStore.Round1MessageBytes(2)),
			}),
		},
		OutputMessages: []*dkg.SignedMessage{
			testingutils.SignDKGMsg2(ks.DKGOperators[1].SK, 1, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frostutils.KeygenMsgStore.PreparationMessageBytes(1),
			}),
			testingutils.SignDKGMsg2(ks.DKGOperators[1].SK, 1, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frostutils.KeygenMsgStore.Round1MessageBytes(1),
			}),
			testingutils.SignDKGMsg2(ks.DKGOperators[1].SK, 1, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data: BlameMessageBytes(2, frost.InconsistentMessage, []*dkg.SignedMessage{
					testingutils.SignDKGMsg2(ks.DKGOperators[2].SK, 2, &dkg.Message{
						MsgType:    dkg.ProtocolMsgType,
						Identifier: identifier,
						Data:       frostutils.KeygenMsgStore.Round1MessageBytes(2),
					}),
					testingutils.SignDKGMsg2(ks.DKGOperators[2].SK, 2, &dkg.Message{
						MsgType:    dkg.ProtocolMsgType,
						Identifier: identifier,
						Data:       makeInvalidForInconsistentMessage(frostutils.KeygenMsgStore.Round1MessageBytes(2)),
					}),
				}),
			}),
		},
		Output:        map[types.OperatorID]*dkg.SignedOutput{},
		KeySet:        ks,
		ExpectedError: "",
	}
}
