package frost

import (
	"github.com/bloxapp/ssv-spec/types"
	"github.com/herumi/bls-eth-go-binary/bls"
)

func (fr *FROST) processRound1() error {
	if !fr.needToRunThisRound(Round1) {
		return nil
	}
	skI, err := fr.partialInterpolate()
	if err != nil {
		return err
	}

	bCastMessage, p2pMessages, err := fr.state.participant.Round1(skI)
	if err != nil {
		return err
	}

	commitments := make([][]byte, 0)
	for _, commitment := range bCastMessage.Verifiers.Commitments {
		commitments = append(commitments, commitment.ToAffineCompressed())
	}

	shares := make(map[uint32][]byte)
	for _, operatorID := range fr.state.operators {
		if uint32(fr.state.operatorID) == operatorID {
			continue
		}

		share := &bls.SecretKey{}
		shamirShare := p2pMessages[operatorID]
		if err := share.Deserialize(shamirShare.Value); err != nil {
			return err
		}

		fr.state.operatorShares[operatorID] = share

		encryptedShare, err := fr.encryptByOperatorID(operatorID, shamirShare.Value)
		if err != nil {
			return err
		}
		shares[operatorID] = encryptedShare
	}

	fr.state.currentRound = Round1
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

func (fr *FROST) partialInterpolate() ([]byte, error) {
	if !fr.isResharing() {
		return nil, nil
	}

	skI := new(bls.Fr)
	indices := make([]bls.Fr, fr.state.oldKeyGenOutput.Threshold+1)
	values := make([]bls.Fr, fr.state.oldKeyGenOutput.Threshold+1)
	for i, id := range fr.state.operatorsOld {
		(&indices[i]).SetInt64(int64(id))
		if types.OperatorID(id) == fr.state.operatorID {
			(&values[i]).Deserialize(fr.state.oldKeyGenOutput.Share.Serialize())
		} else {
			(&values[i]).SetInt64(0)
		}
	}
	err := bls.FrLagrangeInterpolation(skI, indices, values)
	if err != nil {
		return nil, err
	}
	return skI.Serialize(), nil
}
