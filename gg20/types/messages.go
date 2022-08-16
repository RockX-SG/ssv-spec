package types

import (
	"encoding/json"
	"errors"

	"github.com/bloxapp/ssv-spec/dkg/types"
)

type Round1Msg struct {
	Commitment []byte `json:"commitment,omitempty"`
}

type Round2Msg struct {
	Decommitment [][]byte `json:"decommitment,omitempty"`
	BlindFactor  []byte   `json:"blind_factor,omitempty"`
}

type Round3Msg struct {
	Share []byte `json:"share,omitempty,omitempty"`
}

type Round4Msg struct {
	Commitment        []byte `json:"commitment,omitempty"`
	PubKey            []byte `json:"pub_key,omitempty"`
	ChallengeResponse []byte `json:"challenge_response,omitempty"`
}

type KeygenMsgBody struct {
	Round1 *Round1Msg `json:"round1,omitempty"`
	Round2 *Round2Msg `json:"round2,omitempty"`
	Round3 *Round3Msg `json:"round3,omitempty"`
	Round4 *Round4Msg `json:"round4,omitempty"`
}

/*
 * It has the same shape as base.Message except the data is parsed into KeygenMsgBody
 */
type ParsedMessage struct {
	Header    *types.MessageHeader `json:"header,omitempty"`
	Body      *KeygenMsgBody       `json:"body,omitempty"`
	Signature []byte               `json:"signature,omitempty"`
}

func (x *ParsedMessage) GetRoot() ([]byte, error) {
	baseMsg, err := x.ToBase()
	if err != nil {
		return nil, err
	}
	return baseMsg.GetRoot()
}

func (x *ParsedMessage) SetSignature(bytes []byte) error {
	x.Signature = bytes
	return nil
}

func (x *ParsedMessage) FromBase(base *types.Message) error {
	x.Header = base.Header
	x.Signature = base.Signature
	return json.Unmarshal(base.Data, &x.Body)
}

func (x *ParsedMessage) ToBase() (*types.Message, error) {
	body, err := json.Marshal(x.Body)
	if err != nil {
		return nil, err
	}

	return &types.Message{
		Header:    x.Header,
		Data:      body,
		Signature: x.Signature,
	}, nil
}

func (x *ParsedMessage) IsValid() bool {
	cnt := 0
	if x.Body.Round1 != nil {
		cnt += 1
	}
	if x.Body.Round2 != nil {
		cnt += 1
	}
	if x.Body.Round3 != nil {
		cnt += 1
	}
	if x.Body.Round4 != nil {
		cnt += 1
	}
	return cnt == 1
}

func (x *ParsedMessage) GetRoundNumber() (int, error) {
	if x.Body.Round1 != nil {
		return 1, nil
	}
	if x.Body.Round2 != nil {
		return 2, nil
	}
	if x.Body.Round3 != nil {
		return 3, nil
	}
	if x.Body.Round4 != nil {
		return 4, nil
	}
	return 0, errors.New("invalid round")
}

type ParsedMessages = []*ParsedMessage
