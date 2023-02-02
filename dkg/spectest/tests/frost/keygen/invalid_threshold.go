package keygen

import (
	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/dkg/frost"
	"github.com/bloxapp/ssv-spec/dkg/spectest/tests"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
)

func InvalidThreshold() *tests.MsgProcessingSpecTest {
	ks := testingutils.TestingKeygenKeySet()
	network := testingutils.NewTestingNetwork()
	storage := testingutils.NewTestingStorage()
	keyManager := testingutils.NewTestingKeyManager()

	identifier := dkg.NewRequestID(ks.DKGOperators[1].ETHAddress, 1)

	init := testingutils.InitMessageData(
		[]types.OperatorID{1, 2, 3, 4},
		uint16(2),
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
		Name:        "keygen/invalid-threshold",
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
		ExpectedError:  "could not start new dkg: init message invalid: invalid threshold which has to be 2f+1",
	}
}
