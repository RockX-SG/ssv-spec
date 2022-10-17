package frost

import (
	"bytes"
	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/coinbase/kryptology/pkg/sharing"
	ecies "github.com/ecies/go/v2"
	"github.com/pkg/errors"
)

func (fr *FROST) processBlame() (*dkg.BlameOutput, error) {

	for operatorID, msg := range fr.state.msgs[Blame] {

		protocolMessage := &ProtocolMsg{}
		if err := protocolMessage.Decode(msg.Message.Data); err != nil {
			return nil, errors.New("failed to decode blame data")
		}

		var (
			valid bool
			err   error
		)

		switch protocolMessage.BlameMessage.Type {
		case InvalidShare:
			valid, err = fr.processBlameTypeInvalidShare(operatorID, protocolMessage.BlameMessage)

		case InconsistentMessage:
			valid, err = fr.processBlameTypeInconsistentMessage(operatorID, protocolMessage.BlameMessage)
		}

		if err != nil {
			return nil, err
		}

		serializedSigneMessage, err := msg.Encode()
		if err != nil {
			return nil, err
		}
		blameOutput := &dkg.BlameOutput{
			Valid:        valid,
			BlameMessage: serializedSigneMessage,
		}
		return blameOutput, nil
	}

	return nil, nil
}

func (fr *FROST) processBlameTypeInvalidShare(operatorID uint32, blameMessage *BlameMessage) (bool /*valid*/, error) {

	if len(blameMessage.BlameData) != 1 {
		return false, errors.New("invalid blame data")
	}

	round1Message := &Round1Message{}
	if err := round1Message.Decode(blameMessage.BlameData[0]); err != nil {
		return false, err
	}

	verifiers := new(sharing.FeldmanVerifier)
	for _, commitmentBytes := range round1Message.Commitment {
		commitment, err := thisCurve.Point.FromAffineCompressed(commitmentBytes)
		if err != nil {
			return false, err
		}
		verifiers.Commitments = append(verifiers.Commitments, commitment)
	}

	blamerSessionSK := ecies.NewPrivateKeyFromBytes(blameMessage.BlamerSessionSk)
	shareBytes, err := ecies.Decrypt(blamerSessionSK, round1Message.Shares[operatorID])
	if err != nil {
		return false, err
	}

	share := &sharing.ShamirShare{
		Id:    operatorID,
		Value: shareBytes,
	}

	err = verifiers.Verify(share)
	if err == nil {
		return false, nil // blame request is invalid since share is valid
	}
	if err != nil && err.Error() != "not equal" {
		return false, err
	}
	return true, nil // err.Error() == "not equal" -> blame request is valid
}

func (fr *FROST) processBlameTypeInconsistentMessage(operatorID uint32, blameMessage *BlameMessage) (bool /*valid*/, error) {

	if len(blameMessage.BlameData) != 2 {
		return false, errors.New("invalid blame data")
	}

	var originalMessage, newMessage dkg.SignedMessage
	if err := originalMessage.Decode(blameMessage.BlameData[0]); err != nil {
		return false, err
	}
	if err := newMessage.Decode(blameMessage.BlameData[1]); err != nil {
		return false, err
	}

	// if data hash is not equal then the blame request is valid
	return !fr.haveSameRoot(&originalMessage, &newMessage), nil
}

func (fr *FROST) createAndBroadcastBlameOfInconsistentMessage(originalMessage, newMessage *dkg.SignedMessage) error {

	originalMessageBytes, err := originalMessage.Encode()
	if err != nil {
		return err
	}

	newMessageBytes, err := newMessage.Encode()
	if err != nil {
		return err
	}

	blameData := make([][]byte, 0)
	blameData = append(blameData, originalMessageBytes, newMessageBytes)

	fr.state.currentRound = Blame
	msg := &ProtocolMsg{
		Round: Blame,
		BlameMessage: &BlameMessage{
			Type:             InconsistentMessage,
			TargetOperatorID: uint32(newMessage.Signer),
			BlameData:        blameData,
			BlamerSessionSk:  fr.state.sessionSK.Bytes(),
		},
	}
	return fr.broadcastDKGMessage(msg)
}

func (fr *FROST) createAndBroadcastBlameOfInvalidShare(operatorID uint32) error {

	round1Bytes, err := fr.state.msgs[Round1][operatorID].Encode()
	if err != nil {
		return err
	}
	blameData := [][]byte{round1Bytes}

	fr.state.currentRound = Blame
	msg := &ProtocolMsg{
		Round: Blame,
		BlameMessage: &BlameMessage{
			Type:             InvalidShare,
			TargetOperatorID: operatorID,
			BlameData:        blameData,
			BlamerSessionSk:  fr.state.sessionSK.Bytes(),
		},
	}
	return fr.broadcastDKGMessage(msg)
}

func (fr *FROST) haveSameRoot(originalMessage, newMessage *dkg.SignedMessage) bool {
	r1, err := originalMessage.GetRoot()
	if err != nil {
		return false
	}
	r2, err := newMessage.GetRoot()
	if err != nil {
		return false
	}
	return bytes.Compare(r1, r2) == 0
}
