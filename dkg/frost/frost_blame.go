package frost

import (
	"bytes"
	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/coinbase/kryptology/pkg/sharing"
	ecies "github.com/ecies/go/v2"
	"github.com/pkg/errors"
)

func (fr *FROST) checkBlame(blamerOID uint32, protocolMessage *ProtocolMsg) (bool, error) {
	switch protocolMessage.BlameMessage.Type {
	case InvalidShare:
		return fr.processBlameTypeInvalidShare(blamerOID, protocolMessage.BlameMessage)
	case InconsistentMessage:
		return fr.processBlameTypeInconsistentMessage(blamerOID, protocolMessage.BlameMessage)
	case InvalidMessage:
		return fr.processBlameTypeInvalidMessage(blamerOID, protocolMessage.BlameMessage)
	default:
		return false, errors.New("unrecognized blame type")
	}
}

func (fr *FROST) processBlameTypeInvalidShare(operatorID uint32, blameMessage *BlameMessage) (bool /*valid*/, error) {
	if err := blameMessage.Validate(); err != nil {
		return false, errors.Wrap(err, "invalid blame message")
	}
	if len(blameMessage.BlameData) != 1 {
		return false, errors.New("invalid blame data")
	}
	signedMessage := &dkg.SignedMessage{}
	if err := signedMessage.Decode(blameMessage.BlameData[0]); err != nil {
		return false, errors.Wrap(err, "unable to decode BlameData")
	}
	if err := fr.validateSignedMessage(signedMessage); err != nil {
		return false, errors.Wrap(err, "failed to Validate signature for blame data")
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
		return true, nil
	}

	share := &sharing.ShamirShare{
		Id:    operatorID,
		Value: shareBytes,
	}

	if err = verifiers.Verify(share); err != nil {
		return true, nil
	}
	return false, err
}

func (fr *FROST) decodeMessage(data []byte) (*dkg.SignedMessage, *ProtocolMsg, error) {
	signedMsg := &dkg.SignedMessage{}
	if err := signedMsg.Decode(data); err != nil {
		return nil, nil, errors.Wrap(err, "failed to decode signed message")
	}
	pMsg := &ProtocolMsg{}
	if err := pMsg.Decode(signedMsg.Message.Data); err != nil {
		return signedMsg, nil, errors.Wrap(err, "failed to decode protocol msg")
	}
	return signedMsg, pMsg, nil
}

func (fr *FROST) processBlameTypeInconsistentMessage(operatorID uint32, blameMessage *BlameMessage) (bool /*valid*/, error) {
	if err := blameMessage.Validate(); err != nil {
		return false, errors.Wrap(err, "invalid blame message")
	}

	if len(blameMessage.BlameData) != 2 {
		return false, errors.New("invalid blame data")
	}

	signedMsg1, protocolMessage1, err := fr.decodeMessage(blameMessage.BlameData[0])

	if err != nil {
		return false, err
	} else if err := fr.validateSignedMessage(signedMsg1); err != nil {
		return false, errors.Wrap(err, "failed to validate signed message in blame data")
	} else if err := protocolMessage1.Validate(); err != nil {
		return false, errors.New("invalid protocol message")
	}

	signedMsg2, protocolMessage2, err := fr.decodeMessage(blameMessage.BlameData[1])

	if err != nil {
		return false, err
	} else if err := fr.validateSignedMessage(signedMsg2); err != nil {
		return false, errors.Wrap(err, "failed to validate signed message in blame data")
	} else if err := protocolMessage2.Validate(); err != nil {
		return false, errors.New("invalid protocol message")
	}

	if fr.haveSameRoot(signedMsg1, signedMsg2) {
		return false, errors.New("the two messages are consistent")
	}

	if protocolMessage1.Round != protocolMessage2.Round {
		return false, errors.New("the two messages don't belong the the same round")
	}

	return true, nil
}

func (fr *FROST) processBlameTypeInvalidMessage(operatorID uint32, blameMessage *BlameMessage) (bool /*valid*/, error) {
	if err := blameMessage.Validate(); err != nil {
		return false, errors.Wrap(err, "invalid blame message")
	}
	if len(blameMessage.BlameData) != 1 {
		return false, errors.New("invalid blame data")
	}
	signedMsg, pMsg, err := fr.decodeMessage(blameMessage.BlameData[0])
	if err != nil {
		return false, err
	} else if err := fr.validateSignedMessage(signedMsg); err != nil {
		return false, errors.Wrap(err, "failed to validate signed message in blame data")
	}

	err = pMsg.Validate()
	if err != nil {
		return true, nil
	}
	return false, errors.New("message is valid")
}

func (fr *FROST) createAndBroadcastBlameOfInconsistentMessage(existingMessage, newMessage *dkg.SignedMessage) (*dkg.ProtocolOutcome, error) {
	existingMessageBytes, err := existingMessage.Encode()
	if err != nil {
		return nil, err
	}
	newMessageBytes, err := newMessage.Encode()
	if err != nil {
		return nil, err
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
	signedMessage, err := fr.broadcastDKGMessage(msg)
	return &dkg.ProtocolOutcome{
		BlameOutput: &dkg.BlameOutput{
			Valid:        true,
			BlameMessage: signedMessage,
		},
	}, err
}

func (fr *FROST) createAndBroadcastBlameOfInvalidShare(operatorID uint32) (*dkg.ProtocolOutcome, error) {
	round1Bytes, err := fr.state.msgs[Round1][operatorID].Encode()
	if err != nil {
		return nil, err
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
	signedMessage, err := fr.broadcastDKGMessage(msg)
	return &dkg.ProtocolOutcome{
		BlameOutput: &dkg.BlameOutput{
			Valid:        true,
			BlameMessage: signedMessage,
		},
	}, err
}

func (fr *FROST) createAndBroadcastBlameOfInvalidMessage(peerOID uint32, message *dkg.SignedMessage) (*dkg.ProtocolOutcome, error) {
	bytes, err := message.Encode()
	if err != nil {
		return nil, err
	}

	msg := &ProtocolMsg{
		Round: Blame,
		BlameMessage: &BlameMessage{
			Type:             InvalidMessage,
			TargetOperatorID: peerOID,
			BlameData:        [][]byte{bytes},
			BlamerSessionSk:  fr.state.sessionSK.Bytes(),
		},
	}
	signedMsg, err := fr.broadcastDKGMessage(msg)

	return &dkg.ProtocolOutcome{
		BlameOutput: &dkg.BlameOutput{
			Valid:        true,
			BlameMessage: signedMsg,
		},
	}, err
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
