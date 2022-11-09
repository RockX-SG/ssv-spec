package spectest

import (
	"testing"

	fr "github.com/bloxapp/ssv-spec/dkg/frost"

	"github.com/bloxapp/ssv-spec/dkg/spectest/tests"
	"github.com/bloxapp/ssv-spec/dkg/spectest/tests/frost"
)

type SpecTest interface {
	TestName() string
	Run(t *testing.T)
}

var AllTests = []SpecTest{
	tests.HappyFlow(),

	frost.Keygen(),
	frost.Resharing(),
	frost.BlameHappyFlow()[fr.FailedEcies],
	frost.BlameHappyFlow()[fr.InvalidCommitment],
	frost.BlameHappyFlow()[fr.InvalidScaler],
	frost.BlameTypeInvalidShare(),
	frost.BlameTypeInconsistentMessage(),
	tests.ResharingHappyFlow(),
}
