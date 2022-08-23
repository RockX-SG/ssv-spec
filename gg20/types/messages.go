package types

import (
	"encoding/json"
	"errors"
)

type Round1Msg struct {
	Commitment []byte `json:"commitment"`
}

type Round2Msg struct {
	Decommitment [][]byte `json:"decommitment"`
	BlindFactor  []byte   `json:"blind_factor"`
}

type Round3Msg struct {
	Share []byte `json:"share"`
}

type Round4Msg struct {
	Commitment        []byte `json:"commitment"`
	PubKey            []byte `json:"pub_key"`
	ChallengeResponse []byte `json:"challenge_response"`
}

type KeygenMessage struct {
	Receiver uint64     `json:"receiver"`
	Round1   *Round1Msg `json:"round1,omitempty"`
	Round2   *Round2Msg `json:"round2,omitempty"`
	Round3   *Round3Msg `json:"round3,omitempty"`
	Round4   *Round4Msg `json:"round4,omitempty"`
}

// Encode returns a msg encoded bytes or error
func (x *KeygenMessage) Encode() ([]byte, error) {
	return json.Marshal(x)
}

// Decode returns error if decoding failed
func (x *KeygenMessage) Decode(data []byte) error {
	return json.Unmarshal(data, x)
}

//func (x *KeygenMessage) GetRoot() ([]byte, error) {
//	baseMsg, err := x.ToBase()
//	if err != nil {
//		return nil, err
//	}
//	return baseMsg.GetRoot()
//}
//
//func (x *KeygenMessage) SetSignature(bytes []byte) error {
//	x.Signature = bytes
//	return nil
//}
//
//func (x *KeygenMessage) FromBase(base *types.Message) error {
//	x.Header = base.Header
//	x.Signature = base.Signature
//	return json.Unmarshal(base.Data, &x.Body)
//}
//
//func (x *KeygenMessage) ToBase() (*types.Message, error) {
//	body, err := json.Marshal(x.Body)
//	if err != nil {
//		return nil, err
//	}
//
//	return &types.Message{
//		Header:    x.Header,
//		Data:      body,
//		Signature: x.Signature,
//	}, nil
//}

func (x *KeygenMessage) IsValid() bool {
	cnt := 0
	if x.Round1 != nil {
		cnt += 1
	}
	if x.Round2 != nil {
		cnt += 1
	}
	if x.Round3 != nil {
		cnt += 1
	}
	if x.Round4 != nil {
		cnt += 1
	}
	return cnt == 1
}

func (x *KeygenMessage) GetRoundNumber() (int, error) {
	if x.Round1 != nil {
		return 1, nil
	}
	if x.Round2 != nil {
		return 2, nil
	}
	if x.Round3 != nil {
		return 3, nil
	}
	if x.Round4 != nil {
		return 4, nil
	}
	return 0, errors.New("invalid round")
}

type KeygenMessages = []*KeygenMessage
