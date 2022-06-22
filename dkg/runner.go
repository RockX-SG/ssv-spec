package dkg

import (
	"github.com/bloxapp/ssv-spec/types"
	"github.com/pkg/errors"
)

// Runner manages the execution of a DKG, start to finish.
type Runner struct {
	Operator *Operator
	// InitMsg holds the init method which started this runner
	InitMsg *Init
	// Identifier unique for DKG session
	Identifier RequestID
	// ProtocolOutput holds the protocol output once it finishes
	ProtocolOutput *ProtocolOutput
	// PartialSignatures holds partial sigs on deposit data
	PartialSignatures map[types.OperatorID][]byte
	I                 uint16

	keygenSubProtocol Protocol
	signSubProtocol   Protocol
	config            *Config
}

func (r *Runner) Start() error {
	data, err := r.InitMsg.Encode()
	if err != nil {
		return err
	}
	outgoing, err := r.keygenSubProtocol.ProcessMsg(&Message{
		MsgType:    InitMsgType,
		Identifier: r.Identifier,
		Data:       data,
	})
	if err != nil {
		return err
	}
	for _, message := range outgoing {
		err = r.signAndBroadcast(&message)
		if err != nil {
			return err
		}
	}
	return nil
}

// ProcessMsg processes a DKG signed message and returns true and signed output if finished
func (r *Runner) ProcessMsg(msg *SignedMessage) (bool, *SignedOutput, error) {
	// TODO - validate message

	switch msg.Message.MsgType {
	case ProtocolMsgType:
		outgoing, err := r.keygenSubProtocol.ProcessMsg(msg.Message)
		if err != nil {
			return false, nil, errors.Wrap(err, "failed to process dkg msg")
		}
		err = r.broadcastMessages(outgoing, ProtocolMsgType)
		if err != nil {
			return false, nil, err
		}

		if hasOutput(outgoing, KeygenOutputType) {
			outputMsg := outgoing[len(outgoing)-1]
			keygenOutput := &KeygenOutput{}
			err = keygenOutput.Decode(outputMsg.Data)
			if err != nil {
				return false, nil, err
			}
			r.signSubProtocol = NewSignDepositData(r.InitMsg, keygenOutput, ProtocolConfig{
				Identifier:    r.Identifier,
				Operator:      r.Operator,
				BeaconNetwork: r.config.BeaconNetwork,
				Signer:        r.config.Signer,
			})
			outgoing1, err := r.signSubProtocol.Start()
			if err != nil {
				return false, nil, err
			}
			err = r.broadcastMessages(outgoing1, ProtocolMsgType)
		}
	case PartialSigType:
		outgoing, err := r.signSubProtocol.ProcessMsg(msg.Message)
		if err != nil {
			return false, nil, errors.Wrap(err, "failed to partial sig msg")
		}
		if hasOutput(outgoing, PartialOutputMsgType) {
			return true, nil, err
		}

		// TODO: Do we need to aggregate the signed outputs.
	default:
		return false, nil, errors.New("msg type invalid")
	}

	return false, nil, nil
}

func (r *Runner) generateSignedOutput(o *Output) (*SignedOutput, error) {
	sig, err := r.config.Signer.SignDKGOutput(o, r.Operator.ETHAddress)
	if err != nil {
		return nil, errors.Wrap(err, "could not sign output")
	}

	return &SignedOutput{
		Data:      o,
		Signer:    r.Operator.OperatorID,
		Signature: sig,
	}, nil
}

func (r *Runner) broadcastMessages(msgs []Message, msgType MsgType) error {
	for _, message := range msgs {
		if message.MsgType == msgType {
			err := r.signAndBroadcast(&message)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Runner) signAndBroadcast(msg *Message) error {
	sig, err := r.config.Signer.SignDKGOutput(msg, r.Operator.ETHAddress)
	if err != nil {
		return err
	}
	r.config.Network.Broadcast(&SignedMessage{
		Message:   msg,
		Signer:    r.Operator.OperatorID,
		Signature: sig,
	})
	return nil
}

func hasOutput(msgs []Message, msgType MsgType) bool {
	return msgs != nil && len(msgs) > 0 && msgs[len(msgs)-1].MsgType == msgType
}
