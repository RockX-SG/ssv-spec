package types

import (
	"errors"
	"github.com/bloxapp/ssv-spec/dkg/types"
	"github.com/golang/protobuf/proto"
)

func (x *ParsedKGMessage) GetRoot() ([]byte, error) {
	baseMsg, err := x.ToBase()
	if err != nil {
		return nil, err
	}
	return baseMsg.GetRoot()
}

func (x *ParsedKGMessage) SetSignature(bytes []byte) error {
	x.Signature = bytes
	return nil
}

func (x *ParsedKGMessage) FromBase(base *types.Message) error {
	raw, err := proto.Marshal(base)
	if err != nil {
		return err
	}
	return proto.Unmarshal(raw, x)
}

func (x *ParsedKGMessage) ToBase() (*types.Message, error) {
	raw, err := proto.Marshal(x)
	if err != nil {
		return nil, err
	}
	base := &types.Message{}
	err = proto.Unmarshal(raw, base)
	if err != nil {
		return nil, err
	}
	return base, nil
}

func (x *ParsedKGMessage) IsValid() bool {
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

func (x *ParsedKGMessage) GetRoundNumber() (int, error) {
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

type ParsedMessages = []*ParsedKGMessage
