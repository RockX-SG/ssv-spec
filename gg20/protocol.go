package gg20

import (
	"bytes"
	"github.com/bloxapp/ssv-spec/dkg"
	types2 "github.com/bloxapp/ssv-spec/gg20/types"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type KGProtocol struct {
	Signer          types.DKGSigner
	Network         dkg.Network
	Identifier      dkg.RequestID
	Operator        types.OperatorID
	OperatorAddress common.Address
	Init            dkg.Init
	State           *Keygen
}

//func (k *KGProtocol) Output() ([]byte, error) {
//	if k.State == nil || k.State.Output == nil {
//		return nil, nil
//	}
//
//	return k.State.Output.Encode()
//}

//Protocol(n.config.Network, n.operator.OperatorID, id)
func New(signer types.DKGSigner, network dkg.Network, operatorId types.OperatorID, operatorAddress common.Address, identifier dkg.RequestID) (dkg.KeyGenProtocol, error) {
	return &KGProtocol{
		Signer:          signer,
		Network:         network,
		Identifier:      identifier,
		OperatorAddress: operatorAddress,
		Operator:        operatorId,
	}, nil
}

func (k *KGProtocol) Start(init *dkg.Init) error {
	var ids []uint64
	for _, id := range init.OperatorIDs {
		ids = append(ids, uint64(id))
	}
	state, err := NewKeygen(k.Identifier[:], uint64(k.Operator), uint64(init.Threshold), ids)
	if err != nil {
		return err
	}
	k.State = state
	if err := k.State.Proceed(); err != nil {
		return err
	}
	outgoing, err := k.getAndEncodeOutgoing()
	if err != nil {
		return err
	}
	for _, message := range outgoing {
		err = k.signAndBroadcast(message)
		if err != nil {
			return err
		}
	}
	return nil
}

func (k *KGProtocol) ProcessMsg(msg *dkg.SignedMessage) (bool, *dkg.KeyGenOutput, error) {
	if msg == nil {
		return false, nil, errors.New("nil message")
	}
	if int32(msg.Message.MsgType) != k.State.HandleMessageType {
		return false, nil, errors.New("not valid message type")
	}
	if bytes.Compare(msg.Message.Identifier[:], k.State.SessionID) != 0 {
		return false, nil, errors.New("invalid Identifier")
	}
	pMsg := &types2.KeygenMessage{}
	if err := pMsg.Decode(msg.Message.Data); err != nil {
		return false, nil, err
	}

	if err := k.State.PushMessage(uint64(msg.Signer), pMsg); err != nil {
		return false, nil, err
	}

	if err := k.State.Proceed(); err != nil {
		return false, nil, err
	}
	outgoing, err := k.getAndEncodeOutgoing()
	if err != nil {
		return false, nil, err
	}
	for _, message := range outgoing {
		err = k.signAndBroadcast(message)
		if err != nil {
			return false, nil, err
		}
	}
	if k.State != nil && k.State.Output != nil {
		return true, k.State.Output, nil
	}

	return false, nil, nil
}

func (k *KGProtocol) getAndEncodeOutgoing() ([]dkg.Message, error) {
	outgoingInner, err := k.State.GetOutgoing()
	if err != nil {
		return nil, err
	}
	var outgoing []dkg.Message
	for _, out := range outgoingInner {

		if data, err := out.Encode(); err == nil {
			msg := dkg.Message{
				MsgType:    dkg.ProtocolMsgType,
				Identifier: k.Identifier,
				Data:       data,
			}
			outgoing = append(outgoing, msg)
		} else {
			// TODO: Log error
			log.Errorf("error: %v", err)
		}
	}
	return outgoing, nil
}

func (k *KGProtocol) signAndBroadcast(message dkg.Message) error {
	signedMessage := &dkg.SignedMessage{
		Message:   &message,
		Signer:    k.Operator,
		Signature: nil,
	}
	sig, err := k.Signer.SignDKGOutput(signedMessage, k.OperatorAddress)
	if err != nil {
		return errors.Wrap(err, "failed to sign message")
	}
	signedMessage.Signature = sig
	if err = k.Network.BroadcastDKGMessage(signedMessage); err != nil {
		return errors.Wrap(err, "failed to broadcast message")
	}
	return nil
}
