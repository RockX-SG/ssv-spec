package decided

import (
	"github.com/bloxapp/ssv-spec/qbft"
	"github.com/bloxapp/ssv-spec/qbft/spectest/tests"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
	"github.com/herumi/bls-eth-go-binary/bls"
)

// MultiDecidedInstances tests deciding multiple instances
func MultiDecidedInstances() *tests.ControllerSpecTest {
	identifier := types.NewMsgID(testingutils.TestingValidatorPubKey[:], types.BNRoleAttester)
	instanceData := func(height qbft.Height, postRoot string) *tests.RunInstanceData {
		return &tests.RunInstanceData{
			InputValue: []byte{1, 2, 3, 4},
			InputMessages: []*qbft.SignedMessage{
				testingutils.MultiSignQBFTMsg(
					[]*bls.SecretKey{testingutils.Testing4SharesSet().Shares[1], testingutils.Testing4SharesSet().Shares[2], testingutils.Testing4SharesSet().Shares[3]},
					[]types.OperatorID{1, 2, 3},
					&qbft.Message{
						MsgType:    qbft.CommitMsgType,
						Height:     height,
						Round:      qbft.FirstRound,
						Identifier: identifier[:],
						Data:       testingutils.CommitDataBytes([]byte{1, 2, 3, 4}),
					}),
			},
			DecidedVal:         []byte{1, 2, 3, 4},
			DecidedCnt:         1,
			ControllerPostRoot: postRoot,
		}
	}

	return &tests.ControllerSpecTest{
		Name: "multi decide instances",
		RunInstanceData: []*tests.RunInstanceData{
			instanceData(qbft.FirstHeight, "8a5153ccfbefa992ac8b4af6aad2d050c553a95359d0bc49feaef5c11c7139a2"),
			instanceData(1, "edffa599e2ff18bcb82a63116ab452649fe974b63432b05ab5919df16079fb68"),
			instanceData(2, "42323740998181ec00bfcf28fb8095c8f5fd3e43266ca43f0448b3ef42ac2a60"),
			instanceData(3, "cb17defa61f9e6175884f7ae8f372dabefe601360737e43162c6d52a2fa7f6e4"),
			instanceData(4, "2266f4d33838f251c22dcf787551bb6dd7381b689353b8147853338917dddf37"),
			instanceData(5, "57c0602606e7e5b186a570d9ff9dc80717ba6da075a769057374b9f2ebe81653"),
			instanceData(8, "d8c0f5362ae874ded286627c1076a894d26ab61238c37a0a75bcc2e331822073"),
			instanceData(9, "bb3fc017e5d8670dfa3abb88c325daad35d0b908f6b8c04786b828d94b38065e"),
			instanceData(10, "69203928542ee0add38f855cd115c2fa3237b04e0bdec67204113e858f2bfb1d"),
		},
	}
}
