package postconsensus

import (
	"github.com/bloxapp/ssv-spec/qbft"
	"github.com/bloxapp/ssv-spec/ssv/spectest/tests"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
)

// ValidMessage tests a full valid SignedPostConsensusMessage
func ValidMessage() *tests.MsgProcessingSpecTest {
	dr := testingutils.DecidedRunner()

	msgs := []*types.SSVMessage{
		testingutils.SSVMsgAttester(nil, testingutils.PostConsensusAttestationMsg(ks.Shares[1], 1, qbft.FirstHeight)),
	}

	return &tests.MsgProcessingSpecTest{
		Name:                    "valid SignedPostConsensusMessage",
		Runner:                  dr,
		Messages:                msgs,
		PostDutyRunnerStateRoot: "926e788adee20f009bbe499c55ead2efce02a5a63bd4c00ba6cf6ea244529af6",
	}
}
