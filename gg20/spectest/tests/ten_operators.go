package tests

import (
	dkgtu "github.com/bloxapp/ssv-spec/dkg/testutils"
	"github.com/bloxapp/ssv-spec/gg20/testutils"
	"github.com/bloxapp/ssv-spec/gg20/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
)

func TenOperators() *MsgProcessingSpecTest {
	ks := testingutils.Testing10SharesSet()
	suite := testutils.TestSuiteTenOperators()
	pre := testutils.TenOperatorsInstance
	return &MsgProcessingSpecTest{
		Name:   "happy flow ten operators",
		Pre:    pre,
		KeySet: ks,
		Output: suite.MakeLocalKeyShare(1),
		Messages: []*types.ParsedKGMessage{
			dkgtu.SignDKGMsg(ks.DKGOperators[1].SK, suite.R1(1)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[2].SK, suite.R1(2)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[3].SK, suite.R1(3)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[4].SK, suite.R1(4)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[5].SK, suite.R1(5)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[6].SK, suite.R1(6)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[7].SK, suite.R1(7)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[8].SK, suite.R1(8)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[9].SK, suite.R1(9)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[10].SK, suite.R1(10)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[1].SK, suite.R2(1)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[2].SK, suite.R2(2)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[3].SK, suite.R2(3)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[4].SK, suite.R2(4)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[5].SK, suite.R2(5)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[6].SK, suite.R2(6)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[7].SK, suite.R2(7)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[8].SK, suite.R2(8)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[9].SK, suite.R2(9)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[10].SK, suite.R2(10)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[2].SK, suite.R3(2, 1)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[3].SK, suite.R3(3, 1)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[4].SK, suite.R3(4, 1)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[5].SK, suite.R3(5, 1)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[6].SK, suite.R3(6, 1)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[7].SK, suite.R3(7, 1)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[8].SK, suite.R3(8, 1)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[9].SK, suite.R3(9, 1)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[10].SK, suite.R3(10, 1)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[1].SK, suite.R4(1)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[2].SK, suite.R4(2)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[3].SK, suite.R4(3)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[4].SK, suite.R4(4)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[5].SK, suite.R4(5)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[6].SK, suite.R4(6)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[7].SK, suite.R4(7)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[8].SK, suite.R4(8)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[9].SK, suite.R4(9)).(*types.ParsedKGMessage),
			dkgtu.SignDKGMsg(ks.DKGOperators[10].SK, suite.R4(10)).(*types.ParsedKGMessage),
		},
	}
}
