package frost

import (
	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
)

func Resharing() *FrostSpecTest {

	requestID := testingutils.GetRandRequestID()
	ks := testingutils.Testing13SharesSet()

	threshold := 2
	operators := []types.OperatorID{5, 6, 7, 8}
	operatorsOld := []types.OperatorID{1, 2, 3, 4}

	initMsgBytes := testingutils.InitMessageDataBytes(
		operators,
		uint16(threshold),
		testingutils.TestingWithdrawalCredentials,
		testingutils.TestingForkVersion,
	)

	initMessages := make(map[uint32][]*dkg.SignedMessage)
	for _, operatorID := range append(operators, operatorsOld...) {
		initMessages[uint32(operatorID)] = []*dkg.SignedMessage{
			testingutils.SignDKGMsg(ks.DKGOperators[operatorID].SK, operatorID, &dkg.Message{
				MsgType:    dkg.InitMsgType,
				Identifier: requestID,
				Data:       initMsgBytes,
			}),
		}
	}

	return &FrostSpecTest{
		Name:   "Simple Resharing",
		Keyset: ks,

		RequestID: requestID,
		Threshold: uint64(threshold),
		Operators: operators,

		IsResharing:  true,
		OperatorsOld: operatorsOld,
		OldKeygenOutcomes: &testingutils.TestKeygenOutcome{
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

		ExpectedOutcome: testingutils.TestKeygenOutcome{
			ValidatorPK: "ad8332f589d9fd8e77e3fd7d7b8d9e12a51d670921bbb10d0a8ff14349c67a98c407bd82789c0eadf9bec701fd4b638a",
			Share: map[uint32]string{
				5: "00771ef806c810d1dd0b357649e50ae05cd7258c34c3c8bc8c6b32e2fd36d346",
				6: "7067c7a1b50d2c2fb157faccb2dfdfdb8af688764c8343fa25110483f3327e6b",
				7: "739aa66202b7cec4caaefffe5d6fdde8150f804b1d6ceb6e2153d6aea95450e1",
				8: "020243c0c8ab45a6a2af15634bf7288198f6a02414c712da2607d2e561ed2b83",
			},
			OperatorPubKeys: map[uint32]string{
				5: "87e1a89911de8f07dccace6645f0a9eb83085fcd1821ceaeaa43ed1343d02865a8c611d70656490483dfd634e41e59e4",
				6: "9924c984cfb3e0a1bb845e47e7fc0777088fca2b6b4629603365558117de7d4fa1f35968dd62111b849128dd5f0efd39",
				7: "89a7daacc328fb19a7dc0a4b0cd7ecd3c49e666240e0873df88b7e4ec2918e18d634e42e6a029a0e9e6eaa093f31631a",
				8: "82d9edad038b78edc91433ec1f96424bda76f1fb8dd11ee0f3c80a86b5355ed0918ea212a70b1f4bb4378b254b1de180",
			},
		},
		ExpectedError: "",

		InputMessages: map[int]MessagesForNodes{
			0: initMessages,
		},
	}
}
