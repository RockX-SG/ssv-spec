package roundchange

import (
	"github.com/bloxapp/ssv-spec/qbft"
	"github.com/bloxapp/ssv-spec/qbft/spectest/tests"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
)

// ForceStop tests processing a round change msg when instance force stopped
func ForceStop() tests.SpecTest {
	ks := testingutils.Testing4SharesSet()

	pre := testingutils.BaseInstance()
	pre.State.ProposalAcceptedForCurrentRound = testingutils.TestingProposalMessage(ks.Shares[1], types.OperatorID(1))
	pre.ForceStop()

	msgs := []*qbft.SignedMessage{
		testingutils.TestingRoundChangeMessage(ks.Shares[1], types.OperatorID(1)),
	}

	return &tests.MsgProcessingSpecTest{
		Name:          "force stop round change message",
		Pre:           pre,
		PostRoot:      "b61f5233721865ca43afc68f4ad5045eeb123f6e8f095ce76ecf956dabc74713",
		InputMessages: msgs,
		ExpectedError: "instance stopped processing messages",
	}
}
