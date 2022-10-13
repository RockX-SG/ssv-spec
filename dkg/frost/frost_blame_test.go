package frost

import (
	crand "crypto/rand"
	"encoding/json"
	"testing"

	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
	"github.com/coinbase/kryptology/pkg/sharing"
	ecies "github.com/ecies/go/v2"
	"github.com/stretchr/testify/require"
)

func TestProcessBlameTypeInconsistentMessage(t *testing.T) {

	reqID := testingutils.GetRandRequestID()
	dataBytes, _ := getSignedMessage(reqID, 1, []byte{1, 1, 1, 1}).Encode()
	sameDataBytes, _ := getSignedMessage(reqID, 1, []byte{1, 1, 1, 1}).Encode()
	tamperedDataBytes, _ := getSignedMessage(reqID, 1, []byte{2, 2, 2, 2}).Encode()

	tests := map[string]struct {
		blameMessage *BlameMessage
		expected     bool
	}{
		"blame_req_is_invalid": {
			blameMessage: &BlameMessage{
				Type:      InconsistentMessage,
				BlameData: [][]byte{dataBytes, sameDataBytes},
			},
			expected: false,
		},
		"blame_req_is_valid": {
			blameMessage: &BlameMessage{
				Type:      InconsistentMessage,
				BlameData: [][]byte{dataBytes, tamperedDataBytes},
			},
			expected: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fr := &FROST{}
			got, err := fr.processBlameTypeInconsistentMessage(1, test.blameMessage)
			if err != nil {
				t.Error(err)
			}

			if got != test.expected {
				t.Fatalf("expected %t got %t", test.expected, got)
			}
		})
	}
}

func TestProcessBlameTypeInvalidShare(t *testing.T) {

	// Test with valid share i.e invalid blame request
	feldman, err := sharing.NewFeldman(2, 4, thisCurve)
	if err != nil {
		t.Error(err)
	}

	secret := thisCurve.Scalar.Random(crand.Reader)
	verifiers, shares, err := feldman.SplitTo(secret, crand.Reader, []uint32{1, 2, 3, 4})
	if err != nil {
		t.Error(err)
	}

	commitments := make([][]byte, 0)
	for _, commitment := range verifiers.Commitments {
		commitments = append(commitments, commitment.ToAffineCompressed())
	}

	// blame share received from operator 1
	sessionSK, _ := ecies.GenerateKey()
	operatorShare := shares[0] // share for operatorID 1
	encShare, _ := ecies.Encrypt(sessionSK.PublicKey, operatorShare.Value)

	round1Message := &Round1Message{
		Commitment: commitments,
		Shares: map[uint32][]byte{
			1: encShare,
		},
	}
	round1Bytes, _ := json.Marshal(round1Message)

	blameMessage := &BlameMessage{
		Type:             InvalidShare,
		TargetOperatorID: 1,
		BlameData:        [][]byte{round1Bytes},
		BlamerSessionSk:  sessionSK.Bytes(),
	}

	frost := New(
		testingutils.NewTestingNetwork(),
		2, /* operatorID */
		testingutils.GetRandRequestID(),
		testingutils.NewTestingKeyManager(),
		testingutils.NewTestingStorage(),
	).(*FROST)

	valid, err := frost.processBlameTypeInvalidShare(1, blameMessage)
	if err != nil {
		t.Fatal(err)
	}

	// blame request is invalid
	require.Equal(t, false, valid)

	// Test with invalid share i.e valid blame request
	invalidShare := shares[2].Value
	encInvalidShare, _ := ecies.Encrypt(sessionSK.PublicKey, invalidShare)
	round1Message.Shares[1] = encInvalidShare

	round1Bytes, _ = json.Marshal(round1Message)
	blameMessage.BlameData = [][]byte{round1Bytes}

	valid, err = frost.processBlameTypeInvalidShare(1, blameMessage)
	if err != nil {
		t.Fatal(err)
	}

	// blame request is valid
	require.Equal(t, true, valid)
}

func getSignedMessage(requestID dkg.RequestID, operatorID types.OperatorID, data []byte) *dkg.SignedMessage {
	storage := testingutils.NewTestingStorage()
	signer := testingutils.NewTestingKeyManager()

	signedMessage := &dkg.SignedMessage{
		Message: &dkg.Message{
			MsgType:    dkg.ProtocolMsgType,
			Identifier: requestID,
			Data:       data,
		},
		Signer:    operatorID,
		Signature: nil,
	}

	_, op, _ := storage.GetDKGOperator(operatorID)
	sig, _ := signer.SignDKGOutput(signedMessage, op.ETHAddress)
	signedMessage.Signature = sig
	return signedMessage
}
