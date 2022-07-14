package stubdkg

import (
	blstss "github.com/RockX-SG/bls-tss"
	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
)

// DKG is a stub dkg protocol simulating a real DKG protocol with 3 stages in it
type DKG struct {
	identifier dkg.RequestID
	operatorID types.OperatorID
	init       dkg.Init
	myIndex    uint16
	threshold  uint16
	operators  []types.OperatorID // TODO: Remove? Already included in init.

	validatorPK    []byte
	operatorShares map[types.OperatorID]*bls.SecretKey
	msgs           map[Round][]*KeygenProtocolMsg
	state          *blstss.KeygenSimple
}

func (s *DKG) getOutput() (*dkg.Message, error) {
	jsonStr := s.state.Output()
	if jsonStr == nil {
		return nil, errors.New("unable to find output")
	}
	share, err := normalizeAndDecodeOutput(*jsonStr)
	if err != nil {
		return nil, err
	}
	var sharePubKeys [][]byte
	for _, pk48 := range share.SharePublicKeys {
		pk := make([]byte, 48)
		copy(pk[:], pk48[:])
		sharePubKeys = append(sharePubKeys, pk[:])
	}
	output := &dkg.KeygenOutput{
		Index:           share.Index,
		Threshold:       share.Threshold,
		ShareCount:      share.ShareCount,
		PublicKey:       share.PublicKey[:],
		SecretShare:     share.SecretShare[:],
		SharePublicKeys: sharePubKeys,
	}

	data, err := output.Encode()
	if err != nil {
		return nil, err
	}

	return &dkg.Message{
		MsgType:    dkg.KeygenOutputType,
		Identifier: s.identifier,
		Data:       data,
	}, nil
}

/*
func New(init *dkg.Init, identifier dkg.RequestID, config dkg.ProtocolConfig) dkg.Protocol {
	var myIndex uint16 = 0
	for i, id := range init.OperatorIDs {
		if id == config.Operator.OperatorID {
			myIndex = uint16(i) + 1
		}
	}
	return &DKG{
		init:       *init,
		myIndex:    myIndex,
		threshold:  init.Threshold,
		identifier: identifier,
		operatorID: config.Operator.OperatorID,
		msgs:       map[Round][]*KeygenProtocolMsg{},
	}
}
*/

func (s *DKG) SetOperators(validatorPK []byte, operatorShares map[types.OperatorID]*bls.SecretKey) {
	s.validatorPK = validatorPK
	s.operatorShares = operatorShares
}

func (s *DKG) Start() ([]dkg.Message, error) {
	s.state = blstss.NewKeygenSimple(int(s.myIndex), int(s.threshold), len(s.init.OperatorIDs))
	innerOutgoing := s.state.Init()
	outgoing0, err := decodeOutgoing(innerOutgoing)
	if err != nil {
		return nil, err
	}
	outgoing, err := s.packMessages(outgoing0)
	if err != nil {
		return nil, err
	}
	return outgoing, nil
}

func (s *DKG) ProcessMsg(msg0 *dkg.Message) ([]dkg.Message, error) {
	msg := &KeygenProtocolMsg{}
	err := msg.Decode(msg0.Data)
	if err != nil {
		return nil, err
	}
	if s.msgs[msg.RoundNumber] == nil {
		s.msgs[msg.RoundNumber] = []*KeygenProtocolMsg{}
	}
	s.msgs[msg.RoundNumber] = append(s.msgs[msg.RoundNumber], msg)
	if msg.RoundNumber < 1 || msg.RoundNumber > 4 {
		return nil, errors.New("wrong round number")
	}

	data, err := normalizeAndEncodeMessage(msg)
	if err != nil {
		return nil, err
	}
	finished, innerOutgoing, err := s.state.Handle(*data)
	if err != nil {
		return nil, err
	}
	outgoing0, err := decodeOutgoing(innerOutgoing)
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}
	outgoing, err := s.packMessages(outgoing0)
	if err != nil {
		return nil, err
	}
	if finished {
		output, err := s.getOutput()
		if err != nil {
			return nil, nil
		}
		outgoing = append(outgoing, *output)
		s.state.Free()
	}
	return outgoing, nil

}

func (s *DKG) packMessages(msgs []KeygenProtocolMsg) ([]dkg.Message, error) {
	var outgoing []dkg.Message
	for _, outMsg0 := range msgs {
		data, err := outMsg0.Encode()
		if err != nil {
			return nil, err
		}
		outMsg := dkg.Message{
			MsgType:    dkg.ProtocolMsgType,
			Identifier: s.identifier,
			Data:       data,
		}
		outgoing = append(outgoing, outMsg)
	}
	return outgoing, nil
}
