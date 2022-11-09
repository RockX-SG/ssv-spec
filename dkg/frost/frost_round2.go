package frost

import (
	"github.com/coinbase/kryptology/pkg/dkg/frost"
	"github.com/coinbase/kryptology/pkg/sharing"
	ecies "github.com/ecies/go/v2"
	"github.com/pkg/errors"
)

func (fr *FROST) processRound2() error {

	if !fr.needToRunCurrentRound() {
		return nil
	}

	bcast := make(map[uint32]*frost.Round1Bcast)
	p2psend := make(map[uint32]*sharing.ShamirShare)

	for operatorID, dkgMessage := range fr.state.msgs[Round1] {

		protocolMessage := &ProtocolMsg{}
		if err := protocolMessage.Decode(dkgMessage.Message.Data); err != nil {
			return errors.Wrap(err, "failed to decode protocol msg")
		}

		verifiers := new(sharing.FeldmanVerifier)
		for _, commitmentBytes := range protocolMessage.Round1Message.Commitment {
			commitment, err := thisCurve.Point.FromAffineCompressed(commitmentBytes)
			if err != nil {
				fr.state.currentRound = Blame
				if err2 := fr.createAndBroadcastBlameOfInvalidCommitment(operatorID, commitmentBytes, []byte(err.Error())); err2 != nil {
					return err2
				}

				if blame, err2 := fr.processBlame(); err2 != nil {
					return err2
				} else {
					return ErrBlame{BlameOutput: blame}
				}
			}
			verifiers.Commitments = append(verifiers.Commitments, commitment)
		}

		Wi, err := thisCurve.Scalar.SetBytes(protocolMessage.Round1Message.ProofS)
		if err != nil {
			fr.state.currentRound = Blame
			if err2 := fr.createAndBroadcastBlameOfInvalidScaler(operatorID, protocolMessage.Round1Message.ProofS, []byte(err.Error())); err2 != nil {
				return err2
			}

			if blame, err2 := fr.processBlame(); err2 != nil {
				return err2
			} else {
				return ErrBlame{BlameOutput: blame}
			}
		}
		Ci, err := thisCurve.Scalar.SetBytes(protocolMessage.Round1Message.ProofR)
		if err != nil {
			fr.state.currentRound = Blame
			if err2 := fr.createAndBroadcastBlameOfInvalidScaler(operatorID, protocolMessage.Round1Message.ProofR, []byte(err.Error())); err2 != nil {
				return err2
			}

			if blame, err2 := fr.processBlame(); err2 != nil {
				return err2
			} else {
				return ErrBlame{BlameOutput: blame}
			}
		}

		bcastMessage := &frost.Round1Bcast{
			Verifiers: verifiers,
			Wi:        Wi,
			Ci:        Ci,
		}
		bcast[operatorID] = bcastMessage

		if uint32(fr.state.operatorID) == operatorID {
			continue
		}

		encryptedShare := protocolMessage.Round1Message.Shares[uint32(fr.state.operatorID)]
		shareBytes, err := ecies.Decrypt(fr.state.sessionSK, encryptedShare)
		if err != nil {
			fr.state.currentRound = Blame
			if err2 := fr.createAndBroadcastBlameOfFailedEcies(operatorID, encryptedShare, []byte(err.Error())); err2 != nil {
				return err2
			}

			if blame, err2 := fr.processBlame(); err2 != nil {
				return err2
			} else {
				return ErrBlame{BlameOutput: blame}
			}
		}

		share := &sharing.ShamirShare{
			Id:    uint32(fr.state.operatorID),
			Value: shareBytes,
		}

		p2psend[operatorID] = share

		err = verifiers.Verify(share)
		if err != nil {
			fr.state.currentRound = Blame
			if err2 := fr.createAndBroadcastBlameOfInvalidShare(operatorID); err2 != nil {
				return err2
			}

			if blame, err2 := fr.processBlame(); err2 != nil {
				return err2
			} else {
				return ErrBlame{BlameOutput: blame}
			}
		}
	}

	bCastMessage, err := fr.state.participant.Round2(bcast, p2psend)
	if err != nil {
		return err
	}

	msg := &ProtocolMsg{
		Round: fr.state.currentRound,
		Round2Message: &Round2Message{
			Vk:      bCastMessage.VerificationKey.ToAffineCompressed(),
			VkShare: bCastMessage.VkShare.ToAffineCompressed(),
		},
	}
	return fr.broadcastDKGMessage(msg)
}
