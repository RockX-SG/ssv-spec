package timeout

import (
	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/dkg/common"
	"github.com/bloxapp/ssv-spec/dkg/frost"
	"github.com/bloxapp/ssv-spec/dkg/spectest/tests"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
)

func Timeout_Round2() *tests.MsgProcessingSpecTest {
	ks := testingutils.TestingKeygenKeySet()
	network := testingutils.NewTestingNetwork()
	storage := testingutils.NewTestingStorage()
	keyManager := testingutils.NewTestingKeyManager()

	identifier := dkg.NewRequestID(ks.DKGOperators[1].ETHAddress, 1)
	init := testingutils.InitMessageData(
		[]types.OperatorID{1, 2, 3, 4},
		uint16(ks.Threshold),
		testingutils.TestingWithdrawalCredentials,
		testingutils.TestingForkVersion,
	)
	initBytes, _ := init.Encode()

	testingNode := dkg.NewNode(
		&dkg.Operator{
			OperatorID:           1,
			ETHAddress:           ks.DKGOperators[1].ETHAddress,
			EncryptionPubKey:     &ks.DKGOperators[1].EncryptionKey.PublicKey,
			EncryptionPrivateKey: ks.DKGOperators[1].EncryptionKey,
		},
		&dkg.Config{
			KeygenProtocol:  frost.New,
			ReshareProtocol: frost.NewResharing,
			Network:         network,
			Storage:         storage,
			// SignatureDomainType: sigDomainType,
			Signer: keyManager,
		},
	)

	return &tests.MsgProcessingSpecTest{
		Name:        "timeout/round-2",
		TestingNode: testingNode,
		InputMessages: []*dkg.SignedMessage{
			testingutils.SignDKGMsg(ks.DKGOperators[1].EncryptionKey, 1, &dkg.Message{
				MsgType:    dkg.InitMsgType,
				Identifier: identifier,
				Data:       initBytes,
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[2].EncryptionKey, 2, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_PreparationMessageBytes(2, testingutils.KeygenMsgStore),
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[3].EncryptionKey, 3, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_PreparationMessageBytes(3, testingutils.KeygenMsgStore),
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[4].EncryptionKey, 4, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_PreparationMessageBytes(4, testingutils.KeygenMsgStore),
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[2].EncryptionKey, 2, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_Round1MessageBytes(2, testingutils.KeygenMsgStore),
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[3].EncryptionKey, 3, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_Round1MessageBytes(3, testingutils.KeygenMsgStore),
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[4].EncryptionKey, 4, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_Round1MessageBytes(4, testingutils.KeygenMsgStore),
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[2].EncryptionKey, 2, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_Round2MessageBytes(2, testingutils.KeygenMsgStore),
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[3].EncryptionKey, 3, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_Round2MessageBytes(3, testingutils.KeygenMsgStore),
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[4].EncryptionKey, 4, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_Round2MessageBytes(4, testingutils.KeygenMsgStore),
			}),
		},
		OutputMessages: []*dkg.SignedMessage{
			testingutils.SignDKGMsg(ks.DKGOperators[1].EncryptionKey, 1, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_PreparationMessageBytes(1, testingutils.KeygenMsgStore),
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[1].EncryptionKey, 1, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_Round1MessageBytes(1, testingutils.KeygenMsgStore),
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[1].EncryptionKey, 1, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_Round2MessageBytes(1, testingutils.KeygenMsgStore),
			}),
			testingutils.SignDKGMsg(ks.DKGOperators[1].EncryptionKey, 1, &dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: identifier,
				Data:       frost.Testing_TimeoutMessageBytes(common.Round2),
			}),
		},
		Output:        map[types.OperatorID]*dkg.SignedOutput{},
		KeySet:        ks,
		ExpectedError: "",
		LastMsgDelay:  &delayTime, // last input message is delayed to emulate timeout
	}
}
