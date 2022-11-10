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
			valid, _ = fr.processBlameTypeInvalidShare(operatorID, protocolMessage.BlameMessage)
		case InconsistentMessage:
			valid, _ = fr.processBlameTypeInconsistentMessage(operatorID, protocolMessage.BlameMessage)
		case InvalidScalar:
			valid, _ = fr.processBlameTypeInvalidScalar(operatorID, protocolMessage.BlameMessage)
		case InvalidCommitment:
			valid, _ = fr.processBlameTypeInvalidCommitment(operatorID, protocolMessage.BlameMessage)
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
	signedMessage := &dkg.SignedMessage{}
	if err := signedMessage.Decode(blameMessage.BlameData[0]); err != nil {
		return false, errors.Wrap(err, "unable to decode BlameData")
	}
	if err := fr.validateSignedMessage(signedMessage); err != nil {
		return false, errors.Wrap(err, "failed to validate signature for blame data")
	}
	if signedMessage.Message.Identifier != fr.state.identifier {
		return false, errors.New("the message doesn't belong to this session")
	}

	protocolMessage := ProtocolMsg{}
	if err := protocolMessage.Decode(signedMessage.Message.Data); err != nil {
		return false, errors.Wrap(err, "unable to decode protocolMessage")
	}
	round1Message := protocolMessage.Round1Message

	blamesPrepMessage := fr.state.msgs[Preparation][operatorID]
	prepProtocolMessage := &ProtocolMsg{}
	err := prepProtocolMessage.Decode(blamesPrepMessage.Message.Data)
	if err != nil || prepProtocolMessage.PreparationMessage == nil {
		return false, errors.New("unable to decode blamer's PreparationMessage")
	}

	blamerSessionSK := ecies.NewPrivateKeyFromBytes(blameMessage.BlamerSessionSk)
	blamerSessionPK := blamerSessionSK.PublicKey.Bytes(true)
	if !bytes.Equal(blamerSessionPK, prepProtocolMessage.PreparationMessage.SessionPk) {
		return false, errors.New("blame's session pubkey is invalid")
	}

	verifiers := new(sharing.FeldmanVerifier)
	for _, commitmentBytes := range round1Message.Commitment {
		commitment, err := thisCurve.Point.FromAffineCompressed(commitmentBytes)
		if err != nil {
			return false, err
		}
		verifiers.Commitments = append(verifiers.Commitments, commitment)
	}

	shareBytes, err := ecies.Decrypt(blamerSessionSK, round1Message.Shares[operatorID])
	if err != nil {
		return true, err
	}

	share := &sharing.ShamirShare{
		Id:    operatorID,
		Value: shareBytes,
	}

	if err = verifiers.Verify(share); err == nil {
		return false, nil
	}
	return true, err
}

func (fr *FROST) validateMessage(data []byte) (*dkg.SignedMessage, *ProtocolMsg, error) {
	signedMsg := &dkg.SignedMessage{}
	if err := signedMsg.Decode(data); err != nil {
		return nil, nil, errors.Wrap(err, "failed to decode signed message")
	}
	if err := fr.validateSignedMessage(signedMsg); err != nil {
		return nil, nil, errors.Wrap(err, "failed to validate signature for blame data")
	}
	if signedMsg.Message.Identifier != fr.state.identifier {
		return nil, nil, errors.New("the message doesn't belong to this session")
	}
	pMsg := &ProtocolMsg{}
	if err := pMsg.Decode(signedMsg.Message.Data); err != nil {
		return signedMsg, nil, errors.Wrap(err, "failed to decode protocol msg")
	}
	if !pMsg.validate() {
		return signedMsg, nil, errors.New("invalid protocol message")
	}
	return signedMsg, pMsg, nil
}

func (fr *FROST) processBlameTypeInconsistentMessage(operatorID uint32, blameMessage *BlameMessage) (bool /*valid*/, error) {

	if len(blameMessage.BlameData) != 2 {
		return false, errors.New("invalid blame data")
	}

	signedMsg1, protocolMessage1, err := fr.validateMessage(blameMessage.BlameData[0])

	if err != nil {
		return false, err
	}

	signedMsg2, protocolMessage2, err := fr.validateMessage(blameMessage.BlameData[1])

	if err != nil {
		return false, err
	}

	if fr.haveSameRoot(signedMsg1, signedMsg2) {
		return false, errors.New("the two messages are consistent")
	}

	if protocolMessage1.Round != protocolMessage2.Round {
		return false, errors.New("the two messages don't belong the the same round")
	}

	return true, nil
}

//
//func (fr *FROST) processBlameTypeFailedEcies(operatorID uint32, blameMessage *BlameMessage) (bool /*valid*/, error) {
//
//	if len(blameMessage.BlameData) != 2 {
//		return false, errors.New("invalid blame data")
//	}
//
//	preparationMessage := &ProtocolMsg{}
//	if err := preparationMessage.Decode(fr.state.msgs[Preparation][operatorID].Message.Data); err != nil {
//		return false, errors.Wrap(err, "failed to decode preparation message")
//	}
//
//	_, err := ecies.NewPublicKeyFromBytes(preparationMessage.PreparationMessage.SessionPk)
//
//	if ok := VerifyEciesKeyPair(preparationMessage.PreparationMessage.SessionPk, blameMessage.BlamerSessionSk); !ok {
//		return false, errors.New("blamer's secret key is not consistent with the public key stored in message store ")
//	}
//
//	blamerSK := ecies.NewPrivateKeyFromBytes(blameMessage.BlamerSessionSk)
//	_, err := ecies.Decrypt(blamerSK, blameMessage.BlameData[0] /* encryptedShare */)
//	if err == nil {
//		return false, errors.New("share can be decrypted successfully")
//	} else if err.Error() != string(blameMessage.BlameData[1] /* err string */) {
//		return false, errors.New("ecies failed but err string mismatch")
//	}
//	return true, nil
//}

func (fr *FROST) processBlameTypeInvalidScalar(operatorID uint32, blameMessage *BlameMessage) (bool /*valid*/, error) {
	if len(blameMessage.BlameData) != 1 {
		return false, errors.New("invalid blame data")
	}
	_, pMsg, err := fr.validateMessage(blameMessage.BlameData[0])
	if err != nil {
		return false, err
	}
	if pMsg.PreparationMessage != nil {
		// TODO: Validate Message
		return false, errors.New("not a blame message type")
	}
	if pMsg.Round1Message != nil {
		_, errS := thisCurve.Scalar.SetBytes(pMsg.Round1Message.ProofS)
		_, errR := thisCurve.Scalar.SetBytes(pMsg.Round1Message.ProofR)
		if errS != nil || errR != nil {
			return true, nil
		}
		return false, errors.New("scalars are valid")
	}
	//_, err := thisCurve.Scalar.SetBytes(pMsg.BlameMessage.BlameData[0] /* scalar i.e ProofR or ProofS */)
	//if err == nil {
	//	return false, errors.New("given scalar is valid")
	//}
	//else if err.Error() != string(blameMessage.BlameData[1] /* err string */) {
	//	return false, errors.New("unexpected error")
	//}
	return true, nil
}

func (fr *FROST) processBlameTypeInvalidCommitment(operatorID uint32, blameMessage *BlameMessage) (bool /*valid*/, error) {

	if len(blameMessage.BlameData) != 2 {
		return false, errors.New("invalid blame data")
	}

	_, err := thisCurve.Point.FromAffineCompressed(blameMessage.BlameData[0] /* commitment value */)
	if err == nil {
		return false, errors.New("given curve point is valid")
	} else if err.Error() != string(blameMessage.BlameData[1] /* err string */) {
		return false, errors.New("unexpected error")
	}
	return true, nil
}

func (fr *FROST) createAndBroadcastBlameOfInconsistentMessage(existingMessage, newMessage *dkg.SignedMessage) error {
	existingMessageBytes, err := existingMessage.Encode()
	if err != nil {
		return err
	}
	newMessageBytes, err := newMessage.Encode()
	if err != nil {
		return err
	}
	msg := &ProtocolMsg{
		Round: Blame,
		BlameMessage: &BlameMessage{
			Type:             InconsistentMessage,
			TargetOperatorID: uint32(newMessage.Signer),
			BlameData:        [][]byte{existingMessageBytes, newMessageBytes},
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
	msg := &ProtocolMsg{
		Round: Blame,
		BlameMessage: &BlameMessage{
			Type:             InvalidShare,
			TargetOperatorID: operatorID,
			BlameData:        [][]byte{round1Bytes},
			BlamerSessionSk:  fr.state.sessionSK.Bytes(),
		},
	}
	return fr.broadcastDKGMessage(msg)
}

//func (fr *FROST) createAndBroadcastBlameOfFailedEcies(peerOID uint32, encryptedShare []byte, err []byte) error {
//	msg := &ProtocolMsg{
//		Round: Blame,
//		BlameMessage: &BlameMessage{
//			Type:             FailedEcies,
//			TargetOperatorID: peerOID,
//			BlameData:        [][]byte{encryptedShare, err},
//			BlamerSessionSk:  fr.state.sessionSK.Bytes(),
//		},
//	}
//	return fr.broadcastDKGMessage(msg)
//}

//func (fr *FROST) createAndBroadcastBlameOfInvalidScalar(peerOID uint32, scalar []byte, err []byte) error {
//	msg := &ProtocolMsg{
//		Round: Blame,
//		BlameMessage: &BlameMessage{
//			Type:             InvalidScalar,
//			TargetOperatorID: peerOID,
//			BlameData:        [][]byte{scalar, err},
//			BlamerSessionSk:  fr.state.sessionSK.Bytes(),
//		},
//	}
//	return fr.broadcastDKGMessage(msg)
//}

func (fr *FROST) createAndBroadcastBlameOfInvalidMessage(peerOID uint32, message *dkg.SignedMessage) error {
	bytes, err := message.Encode()
	if err != nil {
		return err
	}

	msg := &ProtocolMsg{
		Round: Blame,
		BlameMessage: &BlameMessage{
			Type:             InvalidScalar,
			TargetOperatorID: peerOID,
			BlameData:        [][]byte{bytes},
			BlamerSessionSk:  fr.state.sessionSK.Bytes(),
		},
	}
	return fr.broadcastDKGMessage(msg)
}

func (fr *FROST) createAndBroadcastBlameOfInvalidCommitment(operatorID uint32, commitment []byte, err []byte) error {
	msg := &ProtocolMsg{
		Round: Blame,
		BlameMessage: &BlameMessage{
			Type:             InvalidCommitment,
			TargetOperatorID: operatorID,
			BlameData:        [][]byte{commitment, err},
			BlamerSessionSk:  fr.state.sessionSK.Bytes(),
		},
	}
	return fr.broadcastDKGMessage(msg)
}

func (fr *FROST) haveSameRoot(existingMessage, newMessage *dkg.SignedMessage) bool {
	r1, err := existingMessage.GetRoot()
	if err != nil {
		return false
	}
	r2, err := newMessage.GetRoot()
	if err != nil {
		return false
	}
	return bytes.Equal(r1, r2)
}

type ErrBlame struct {
	BlameOutput *dkg.BlameOutput
}

func (e ErrBlame) Error() string {
	return "detected and processed blame"
}
