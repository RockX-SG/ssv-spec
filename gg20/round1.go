package gg20

import (
	types2 "github.com/bloxapp/ssv-spec/gg20/types"
)

func (k *Keygen) r1Proceed() error {
	if k.Round != 1 {
		return ErrInvalidRound
	}
	msg := &types2.KeygenMessage{
		Round2: &types2.Round2Msg{
			Decommitment: k.GetDecommitment(),
			BlindFactor:  k.BlindFactor[:],
		},
	}
	k.pushOutgoing(msg)
	k.Round = 2
	return nil
}

func (k *Keygen) r1CanProceed() error {
	if k.Round != 1 {
		return ErrInvalidRound
	}
	for _, id := range k.Committee {
		if msg := k.Round1Msgs[id]; msg == nil {
			return ErrExpectMessage
		}
	}
	return nil
}
