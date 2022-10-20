package frost

import (
	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
)

func Keygen() *FrostSpecTest {

	requestID := testingutils.GetRandRequestID()
	ks := testingutils.Testing4SharesSet()

	threshold := 2
	operators := []types.OperatorID{1, 2, 3, 4}
	initMsgBytes := testingutils.InitMessageDataBytes(
		operators,
		uint16(threshold),
		testingutils.TestingWithdrawalCredentials,
		testingutils.TestingForkVersion,
	)

	initMessages := make(map[uint32][]*dkg.SignedMessage)
	for _, operatorID := range operators {
		initMessages[uint32(operatorID)] = []*dkg.SignedMessage{
			testingutils.SignDKGMsg(ks.DKGOperators[operatorID].SK, operatorID, &dkg.Message{
				MsgType:    dkg.InitMsgType,
				Identifier: requestID,
				Data:       initMsgBytes,
			}),
		}
	}

	return &FrostSpecTest{
		Name:   "Simple Keygen",
		Keyset: ks,

		RequestID: requestID,
		Threshold: uint64(threshold),
		Operators: operators,

		ExpectedOutcome: testingutils.TestKeygenOutcome{
			ValidatorPK: "89a721d38bbcb78c396e61d7cf948b26432c72639bf343903b71989604e7df762c981c950ecd6567d79f98ed5eedb6b7",
			Share: map[uint32]string{
				1: "02f026db6d82c36541076e8020955b658b435e592a03f70dce793d4c07694451",
				2: "5d96593e5b076ee2b2ec7d2e7051790663b6af5d21d2263d47004ef7be6b9a9c",
				3: "665bb970881643fd7881711a41017148b74063798e3375be47f4aaf585810e4b",
				4: "130ed232fce2ddec6d64140ab534a159d52d246b132f4efe4ec4d2a581909e72",
			},
			OperatorPubKeys: map[uint32]string{
				1: "a7fb41890fa546935608ccecf76521d5b6d68288a3f01dfe83e786b0a691705f6661e0aa9bd6a38bf76b1d0d85e344a1",
				2: "894fa7ba56be2a3b9e565a166da3e3a4817f808d8b83e127acaba2a900d7abbfb33691cbda913dd30ca6b7e83dc9232b",
				3: "b89f855865521dbd29b9f4e5306d11ef34bb8806a3a4b8e5d16c43946439c0483ba59b3d8bf2aa960151ff083c1cde29",
				4: "928cc98f610158e532b2caba36a64a511009976393d0566833b45a48396af751bb9a8f79210fcca2eb8bb48bb708e98b",
			},
		},
		ExpectedError: "",

		InputMessages: map[int]MessagesForNodes{
			0: initMessages,
		},
	}
}
