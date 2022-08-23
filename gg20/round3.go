package gg20

import (
	"errors"
	"github.com/bloxapp/ssv-spec/gg20/algorithms/dlog"
	"github.com/bloxapp/ssv-spec/gg20/algorithms/vss"
	types2 "github.com/bloxapp/ssv-spec/gg20/types"
	"github.com/herumi/bls-eth-go-binary/bls"
)

var (
	ErrInvalidShare = errors.New("invalid share")
)

func (k *Keygen) calcSkI() *bls.SecretKey {
	skI := new(bls.SecretKey)
	skI.Deserialize(k.ownShare.Serialize())
	for ind, r3Msg := range k.Round3Msgs {
		if ind == k.PartyI {
			continue
		}
		temp := new(bls.SecretKey)
		temp.Deserialize(r3Msg.Round3.Share)
		skI.Add(temp)
	}
	return skI
}

func (k *Keygen) r3Proceed() error {
	if k.Round != 3 {
		return ErrInvalidRound
	}

	k.skI = k.calcSkI()
	knowledge := dlog.Knowledge{
		SecretKey:    k.skI,
		RandomNumber: k.DlogR,
	}
	proof := knowledge.Prove()
	msg := &types2.KeygenMessage{
		Round4: &types2.Round4Msg{
			Commitment:        proof.Commitment.Serialize(),
			PubKey:            proof.PubKey.Serialize(),
			ChallengeResponse: proof.Response.Serialize(),
		},
	}
	k.pushOutgoing(msg)
	k.Round = 4
	return nil
}

func (k *Keygen) r3CanProceed() error {

	if k.Round != 3 {
		return ErrInvalidRound
	}
	for _, ind := range k.Committee {
		if ind == k.PartyI {
			continue
		}
		r3Msg := k.Round3Msgs[ind]
		r2Msg := k.Round2Msgs[ind]
		if r2Msg == nil || r2Msg.Round2 == nil || r2Msg.Round2.Decommitment == nil || r3Msg == nil || r3Msg.Round3 == nil {
			return ErrExpectMessage
		}
		shareBytes := r3Msg.Round3.Share
		share := &vss.Share{
			Threshold: len(k.Coefficients) - 1,
			ID:        new(bls.Fr),
			Share:     new(bls.Fr),
		}
		share.ID.SetInt64(int64(k.PartyI))
		share.Share.Deserialize(shareBytes)
		if ind == k.PartyI {
			share.Share = k.ownShare
		}
		commitments := make([]*bls.PublicKey, len(k.Coefficients))
		for j, commBytes := range r2Msg.Round2.Decommitment {
			// TODO: Improve conversion of multiple times
			commitments[j] = new(bls.PublicKey)
			commitments[j].Deserialize(commBytes)
		}
		if !share.Verify(len(k.Coefficients)-1, commitments) {
			return ErrInvalidShare
		}
	}

	return nil
}
