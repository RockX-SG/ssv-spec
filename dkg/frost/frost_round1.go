package frost

import (
	"github.com/bloxapp/ssv-spec/types"
	"github.com/herumi/bls-eth-go-binary/bls"
)

func (fr *FROST) processRound1() error {
	if fr.isResharing() && !fr.inOldCommittee() {
		return nil
	}
	skI := fr.partialInterpolate()

	bCastMessage, p2pMessages, err := fr.participant.Round1(skI)
	if err != nil {
		return err
	}

	commitments := make([][]byte, 0)
	for _, commitment := range bCastMessage.Verifiers.Commitments {
		commitments = append(commitments, commitment.ToAffineCompressed())
	}

	shares := make(map[uint32][]byte)
	for _, operatorID := range fr.operators {
		if uint32(fr.operatorID) == operatorID {
			continue
		}

		share := &bls.SecretKey{}
		shamirShare := p2pMessages[operatorID]
		if err := share.Deserialize(shamirShare.Value); err != nil {
			return err
		}

		fr.operatorShares[operatorID] = share

		encryptedShare, err := fr.encryptByOperatorID(operatorID, shamirShare.Value)
		if err != nil {
			return err
		}
		shares[operatorID] = encryptedShare
	}

	fr.currentRound = Round1
	msg := &ProtocolMsg{
		Round: Round1,
		Round1Message: &Round1Message{
			Commitment: commitments,
			ProofS:     bCastMessage.Wi.Bytes(),
			ProofR:     bCastMessage.Ci.Bytes(),
			Shares:     shares,
		},
	}
	return fr.broadcastDKGMessage(msg)
}

func (fr *FROST) partialInterpolate() []byte {
	if !fr.isResharing() {
		return nil
	}

	skI := new(bls.Fr)
	indices := make([]bls.Fr, fr.oldKeyGenOutput.Threshold+1)
	values := make([]bls.Fr, fr.oldKeyGenOutput.Threshold+1)
	for i, id := range fr.operatorsOld {
		(&indices[i]).SetInt64(int64(id))
		if types.OperatorID(id) == fr.operatorID {
			(&values[i]).Deserialize(fr.oldKeyGenOutput.Share.Serialize())
		} else {
			(&values[i]).SetInt64(0)
		}
	}
	bls.FrLagrangeInterpolation(skI, indices, values)
	return skI.Serialize()
}
