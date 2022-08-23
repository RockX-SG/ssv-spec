package gg20

import (
	"errors"
	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/gg20/algorithms/dlog"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/herumi/bls-eth-go-binary/bls"
)

var (
	ErrInvalidProof = errors.New("invalid proof")
)

func (k *Keygen) r4Proceed() error {
	if k.Round != 4 {
		return ErrInvalidRound
	}

	valPK := new(bls.PublicKey)
	for _, r2Msg := range k.Round2Msgs {
		temp := new(bls.PublicKey)
		temp.Deserialize(r2Msg.Round2.Decommitment[0])
		valPK.Add(temp)
	}
	var vkVec map[types.OperatorID]*bls.PublicKey
	for _, id := range k.Committee {
		r4Msg := k.Round4Msgs[id]
		pk := new(bls.PublicKey)
		pk.Deserialize(r4Msg.Round4.PubKey)
		vkVec[types.OperatorID(id)] = pk
	}

	k.Output = &dkg.KeyGenOutput{
		Share:           k.skI,
		OperatorPubKeys: vkVec,
		ValidatorPK:     valPK.Serialize(),
		Threshold:       uint64(len(k.Coefficients) - 1),
	}
	k.Round = 5
	return nil
}

func (k *Keygen) r4CanProceed() error {
	if k.Round != 4 {
		return ErrInvalidRound
	}
	for _, id := range k.Committee {
		r4Msg := k.Round4Msgs[id]
		if r4Msg == nil || r4Msg.Round4 == nil {
			return ErrExpectMessage
		}
		proof := &dlog.Proof{
			Commitment: new(bls.PublicKey),
			PubKey:     new(bls.PublicKey),
			Response:   new(bls.Fr),
		}
		proof.Commitment.Deserialize(r4Msg.Round4.Commitment)
		proof.PubKey.Deserialize(r4Msg.Round4.PubKey)
		proof.Response.Deserialize(r4Msg.Round4.ChallengeResponse)
		if !proof.Verify() {
			return ErrInvalidProof
		}
	}
	return nil
}
