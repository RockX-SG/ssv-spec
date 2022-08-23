package gg20

import (
	"errors"
	"github.com/bloxapp/ssv-spec/dkg"
	types2 "github.com/bloxapp/ssv-spec/gg20/types"
	"github.com/bloxapp/ssv-spec/types"
	log "github.com/sirupsen/logrus"
	"time"
)

type Runner struct {
	Keygen   *Keygen
	incoming <-chan types.SSVMessage
	outgoing chan<- types.SSVMessage
}

func NewRunner(identifier dkg.RequestID, i, t uint64, committee []uint64, incoming <-chan types.SSVMessage, outgoing chan<- types.SSVMessage) (*Runner, error) {
	kg, err := NewKeygen(identifier[:], i, t, committee)
	if err != nil {
		return nil, err
	}
	return &Runner{
		Keygen:   kg,
		incoming: incoming,
		outgoing: outgoing,
	}, nil
}

func (r *Runner) Initialize() error {
	if r.Keygen.Round == 0 {
		return r.Keygen.Proceed()
	}
	return errors.New("state machine is not initializable")
}

func (r *Runner) ProcessLoop() {
	finished := r.Keygen != nil && r.Keygen.Output != nil
	for !finished {
		select {
		case msg, ok := <-r.incoming:
			if ok {
				err := r.process(msg)
				if err != nil {
					// TODO: Log error
				}
			}
		case <-time.After(1 * time.Second):
			finished = r.Keygen.Output != nil
			_ = r.Keygen.Proceed()
			if outgoing, _ := r.Keygen.GetOutgoing(); outgoing != nil {
				for _, out := range outgoing {
					r.signAndBroadcast(out)
				}
			}
			if finished {
				break
			}
		}
	}
}
func (r *Runner) process(msg types.SSVMessage) error {
	if msg.MsgType != types.DKGMsgType {
		return errors.New("not a DKGMsgType")

	}
	signedMsg := &dkg.SignedMessage{}
	err := signedMsg.Decode(msg.Data)
	if err != nil {
		return err
	}
	if signedMsg.Message.MsgType != dkg.ProtocolMsgType {
		return errors.New("not a ProtocolMsgType")
	}
	parsed := &types2.KeygenMessage{}
	if err := parsed.Decode(signedMsg.Message.Data); err != nil {
		return err
	} else {
		r.Keygen.PushMessage(uint64(signedMsg.Signer), parsed)
	}
	return nil
}

func (r *Runner) signAndBroadcast(msg *types2.KeygenMessage) {
	panic("implement")
	//if msg, err := out.ToBase(); err == nil {
	//	r.outgoing <- *msg
	//} else {
	//	// TODO: Standardize log error
	//	log.Errorf("err: %v", err)
	//}
}

func (r *Runner) trace(funcName string, result interface{}) {
	log.WithFields(log.Fields{
		"participant": r.Keygen.PartyI,
		"funcName":    funcName,
		"result":      result,
	}).Trace("statusCheck")
}
