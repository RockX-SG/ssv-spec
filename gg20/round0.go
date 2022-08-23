package gg20

import (
	types2 "github.com/bloxapp/ssv-spec/gg20/types"
)

func (k *Keygen) r0Proceed() error {
	if k.Round != 0 {
		return ErrInvalidRound
	}

	msg := &types2.KeygenMessage{
		Round1: &types2.Round1Msg{
			Commitment: k.GetCommitment(),
		},
	}
	k.pushOutgoing(msg)
	k.Round = 1
	return nil
}

func (k *Keygen) r0CanProceed() error {
	if k.Round != 0 {
		return ErrInvalidRound
	}
	return nil
}
