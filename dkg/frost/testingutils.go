package frost

import (
	"encoding/hex"

	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
	ecies "github.com/ecies/go/v2"
)

var testProtocolRound = Preparation

func testSignedMessage(round ProtocolRound, operatorID types.OperatorID) *dkg.SignedMessage {
	sk := testingutils.TestingKeygenKeySet().DKGOperators[operatorID].SK
	msg := &dkg.Message{
		MsgType:    dkg.ProtocolMsgType,
		Identifier: dkg.NewRequestID(testingutils.TestingKeygenKeySet().DKGOperators[operatorID].ETHAddress, uint32(operatorID)),
	}
	switch round {
	case Preparation:
		msg.Data = Testing_PreparationMessageBytes(operatorID, testingutils.KeygenMsgStore)
	case Round1:
		msg.Data = Testing_Round1MessageBytes(operatorID, testingutils.KeygenMsgStore)
	case Round2:
		msg.Data = Testing_Round2MessageBytes(operatorID, testingutils.KeygenMsgStore)
	case Blame:
		msg.Data = Testing_BlameMessageBytes(operatorID, InvalidMessage, nil)
	}
	return testingutils.SignDKGMsg(sk, operatorID, msg)
}

func Testing_PreparationMessageBytes(id types.OperatorID, frostMsgStore testingutils.FrostMsgStore) []byte {
	encodedData, _ := Testing_PreparationMessage(id, frostMsgStore).Encode()
	return encodedData
}

func Testing_Round1MessageBytes(id types.OperatorID, frostMsgStore testingutils.FrostMsgStore) []byte {
	encodedData, _ := Testing_Round1Message(id, frostMsgStore).Encode()
	return encodedData
}

func Testing_Round2MessageBytes(id types.OperatorID, frostMsgStore testingutils.FrostMsgStore) []byte {
	encodedData, _ := Testing_Round2Message(id, frostMsgStore).Encode()
	return encodedData
}

func Testing_BlameMessageBytes(id types.OperatorID, blameType BlameType, blameMessages []*dkg.SignedMessage) []byte {
	encodedData, _ := Testing_BlameMessage(id, blameType, blameMessages).Encode()
	return encodedData
}
func Testing_TimeoutMessageBytes(round ProtocolRound) []byte {
	encodedData, _ := Testing_TimeoutMessage(round).Encode()
	return encodedData
}

func Testing_PreparationMessage(id types.OperatorID, frostMsgStore testingutils.FrostMsgStore) *ProtocolMsg {
	pk, _ := hex.DecodeString(frostMsgStore.SessionPKs[id])
	return &ProtocolMsg{
		Round: Preparation,
		PreparationMessage: &PreparationMessage{
			SessionPk: pk,
		},
	}
}

func Testing_Round1Message(id types.OperatorID, frostMsgStore testingutils.FrostMsgStore) *ProtocolMsg {
	commitments := make([][]byte, 0)
	for _, commitment := range frostMsgStore.Round1[id].Commitments {
		cbytes, _ := hex.DecodeString(commitment)
		commitments = append(commitments, cbytes)
	}
	proofS, _ := hex.DecodeString(frostMsgStore.Round1[id].ProofS)
	proofR, _ := hex.DecodeString(frostMsgStore.Round1[id].ProofR)
	shares := map[uint32][]byte{}
	for peerID, share := range frostMsgStore.Round1[id].Shares {
		shareBytes, _ := hex.DecodeString(share)
		shares[peerID] = shareBytes
	}
	return &ProtocolMsg{
		Round: Round1,
		Round1Message: &Round1Message{
			Commitment: commitments,
			ProofS:     proofS,
			ProofR:     proofR,
			Shares:     shares,
		},
	}
}

func Testing_Round2Message(id types.OperatorID, frostMsgStore testingutils.FrostMsgStore) *ProtocolMsg {
	vk, _ := hex.DecodeString(frostMsgStore.Round2[id].Vk)
	vkshare, _ := hex.DecodeString(frostMsgStore.Round2[id].VkShare)
	return &ProtocolMsg{
		Round: Round2,
		Round2Message: &Round2Message{
			Vk:      vk,
			VkShare: vkshare,
		},
	}
}

func Testing_BlameMessage(id types.OperatorID, blameType BlameType, blameMessages []*dkg.SignedMessage) *ProtocolMsg {
	blameData := make([][]byte, 0)
	for _, blameMessage := range blameMessages {
		byts, _ := blameMessage.Encode()
		blameData = append(blameData, byts)
	}

	skBytes, _ := hex.DecodeString(testingutils.KeygenMsgStore.SessionSKs[1])
	sk := ecies.NewPrivateKeyFromBytes(skBytes)

	return &ProtocolMsg{
		Round: Blame,
		BlameMessage: &BlameMessage{
			Type:             blameType,
			TargetOperatorID: uint32(id),
			BlameData:        blameData,
			BlamerSessionSk:  sk.Bytes(),
		},
	}
}

func Testing_TimeoutMessage(round ProtocolRound) *ProtocolMsg {
	return &ProtocolMsg{
		Round: Timeout,
		TimeoutMessage: &TimeoutMessage{
			Round: round,
		},
	}
}
