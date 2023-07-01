package dkg

import (
	"bytes"
	"fmt"

	"github.com/bloxapp/ssv-spec/types"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
)

type Runner interface {
	ProcessMsg(msg *SignedMessage) (bool, error)
}

// Runner manages the execution of a DKG, start to finish.
type runner struct {
	Operator *Operator
	// InitMsg holds the init method which started this runner
	InitMsg *Init
	// ReshareMsg holds the reshare method which started this runner
	ReshareMsg *Reshare
	// KeySign holds the signature method which started this runner
	KeySign *KeySign
	// Identifier unique for DKG session
	Identifier RequestID
	// KeygenOutcome holds the protocol outcome once it finishes
	KeygenOutcome *ProtocolOutcome
	// DepositDataRoot is the signing root for the deposit data
	DepositDataRoot []byte
	// DepositDataSignatures holds partial sigs on deposit data
	DepositDataSignatures map[types.OperatorID]*PartialDepositData
	// OutputMsgs holds all output messages received
	OutputMsgs map[types.OperatorID]*SignedOutput

	protocol Protocol
	config   *Config
}

// ProcessMsg processes a DKG signed message and returns true and stream keygen output or blame if finished
func (r *runner) ProcessMsg(msg *SignedMessage) (bool, error) {
	// TODO - validate message
	m := map[MsgType]func(*SignedMessage) (bool, error){
		ProtocolMsgType:    r.processProtocolMsg,
		DepositDataMsgType: r.processDepositDataMsg,
		OutputMsgType:      r.processOutputMsg,
	}
	f, ok := m[msg.Message.MsgType]
	if !ok {
		return false, fmt.Errorf("msg type invalid")
	}
	return f(msg)
}

func (r *runner) processProtocolMsg(msg *SignedMessage) (bool, error) {

	if r.KeygenOutcome != nil && r.KeygenOutcome.isValid() {
		return false, nil
	}

	finished, o, err := r.protocol.ProcessMsg(msg)
	if err != nil {
		return false, fmt.Errorf("failed to process dkg msg: %w", err)
	}
	if !finished {
		return false, nil
	}
	if !o.isValid() {
		fmt.Printf("o=%+v\n", o)
		return false, fmt.Errorf("protcol outcome is invalid")
	}

	r.KeygenOutcome = o

	if r.KeygenOutcome.IsFinishedWithKeygen() {
		if err := r.config.Storage.SaveKeyGenOutput(o.ProtocolOutput); err != nil {
			return false, err
		}

		if r.isResharing() {
			if err := r.prepareAndBroadcastKeyGenOutput(); err != nil {
				return false, err
			}
		} else {
			if err := r.prepareAndBroadcastDepositData(); err != nil {
				return false, err
			}
		}
	}

	if r.KeygenOutcome.IsFinishedWithKeySign() {
		if err := r.prepareAndBroadcastKeySignOutput(); err != nil {
			return false, err
		}
	}

	if r.KeygenOutcome.IsFailedWithBlame() {
		if err := r.config.Network.StreamDKGBlame(r.KeygenOutcome.BlameOutput); err != nil {
			return true, errors.Wrap(err, "failed to stream blame output") //TODO: revisit this logic
		}
	}

	return false, nil
}

func (r *runner) processDepositDataMsg(msg *SignedMessage) (bool, error) {

	depSig := &PartialDepositData{}
	if err := depSig.Decode(msg.Message.Data); err != nil {
		return false, errors.Wrap(err, "could not decode PartialDepositData")
	}

	if err := r.validateDepositDataSig(depSig); err != nil {
		return false, errors.Wrap(err, "PartialDepositData invalid")
	}

	if found := r.DepositDataSignatures[msg.Signer]; found == nil {
		r.DepositDataSignatures[msg.Signer] = depSig
	} else if !bytes.Equal(found.Signature, msg.Signature) {
		return false, errors.New("inconsistent partial signature received")
	}

	if len(r.DepositDataSignatures) == int(r.InitMsg.Threshold) {
		if err := r.prepareAndBroadcastKeyGenOutput(); err != nil {
			return false, err
		}
	}
	return false, nil
}

func (r *runner) processOutputMsg(msg *SignedMessage) (bool, error) {
	output := &SignedOutput{}
	if err := output.Decode(msg.Message.Data); err != nil {
		return false, errors.Wrap(err, "could not decode SignedOutput")
	}

	if err := r.validateSignedOutput(output); err != nil {
		return false, errors.Wrap(err, "signed output invalid")
	}

	r.OutputMsgs[msg.Signer] = output

	// GLNOTE: Actually we need every operator to sign instead only the quorum!
	finished := false
	if r.isKeySign() {
		finished = len(r.OutputMsgs) == len(r.KeySign.Operators)
	} else if !r.isResharing() {
		finished = len(r.OutputMsgs) == len(r.InitMsg.OperatorIDs)
	} else {
		finished = len(r.OutputMsgs) == len(r.ReshareMsg.OperatorIDs)
	}

	if finished {
		err := r.config.Network.StreamDKGOutput(r.OutputMsgs)
		return true, errors.Wrap(err, "failed to stream dkg output")
	}

	return false, nil
}

func (r *runner) validateDepositDataSig(msg *PartialDepositData) error {

	if r.KeygenOutcome == nil ||
		r.KeygenOutcome.ProtocolOutput == nil ||
		r.KeygenOutcome.ProtocolOutput.OperatorPubKeys == nil {

		return errors.New("missing keygen outcome or operator public keys")
	}

	// find operator and verify msg
	sharePK, found := r.KeygenOutcome.ProtocolOutput.OperatorPubKeys[msg.Signer]
	if !found {
		return errors.New("signer not part of committee")
	}
	sig := &bls.Sign{}
	if err := sig.Deserialize(msg.Signature); err != nil {
		return errors.Wrap(err, "could not deserialize partial sig")
	}
	if !sig.VerifyByte(sharePK, r.DepositDataRoot) {
		return errors.New("partial deposit data sig invalid")
	}

	return nil
}

func (r *runner) validateSignedOutput(msg *SignedOutput) error {
	// TODO: Separate fields match and signature validation
	// output := r.ownOutput()
	// if output == nil {
	// 	return fmt.Errorf("own output not found")
	// }

	// if output.Data != nil {
	// 	if output.Data.RequestID != msg.Data.RequestID {
	// 		return errors.New("got mismatching RequestID")
	// 	}
	// 	if !bytes.Equal(output.Data.ValidatorPubKey, msg.Data.ValidatorPubKey) {
	// 		return errors.New("got mismatching ValidatorPubKey")
	// 	}
	// } else if output.BlameData != nil {
	// 	if output.BlameData.RequestID != msg.BlameData.RequestID {
	// 		return errors.New("got mismatching RequestID")
	// 	}
	// } else {
	// 	if output.KeySignData.RequestID != msg.KeySignData.RequestID {
	// 		return errors.New("got mismatching RequestID")
	// 	}
	// }

	found, operator, err := r.config.Storage.GetDKGOperator(msg.Signer)
	if !found {
		return errors.New("unable to find signer")
	}
	if err != nil {
		return errors.Wrap(err, "unable to find signer")
	}

	var (
		data types.Root
	)

	if msg.Data != nil {
		data = msg.Data
	} else if msg.BlameData != nil {
		data = msg.BlameData
	} else {
		data = msg.KeySignData
	}

	root, err := types.ComputeSigningRoot(data, types.ComputeSignatureDomain(r.config.SignatureDomainType, types.DKGSignatureType))
	if err != nil {
		return errors.Wrap(err, "fail to get root")
	}

	isValid := types.Verify(operator.EncryptionPubKey, root, msg.Signature)
	if !isValid {
		return errors.New("invalid signature")
	}
	return nil
}

func (r *runner) prepareAndBroadcastDepositData() error {
	// generate deposit data
	root, _, err := types.GenerateETHDepositData(
		r.KeygenOutcome.ProtocolOutput.ValidatorPK,
		r.InitMsg.WithdrawalCredentials,
		r.InitMsg.Fork,
		types.DomainDeposit,
	)
	if err != nil {
		return errors.Wrap(err, "could not generate deposit data")
	}

	r.DepositDataRoot = root

	// sign
	sig := r.KeygenOutcome.ProtocolOutput.Share.SignByte(root)

	// broadcast
	pdd := &PartialDepositData{
		Signer:    r.Operator.OperatorID,
		Root:      r.DepositDataRoot,
		Signature: sig.Serialize(),
	}
	if err := r.signAndBroadcastMsg(pdd, DepositDataMsgType); err != nil {
		return errors.Wrap(err, "could not broadcast partial deposit data")
	}
	r.DepositDataSignatures[r.Operator.OperatorID] = pdd
	return nil
}

func (r *runner) prepareAndBroadcastKeySignOutput() error {
	o := r.KeygenOutcome.KeySignOutput
	sig, err := r.config.Signer.SignDKGOutput(o, r.Operator.EncryptionPrivateKey)
	if err != nil {
		return errors.Wrap(err, "could not sign output")
	}
	signedOuput := &SignedOutput{
		KeySignData: o,
		Signer:      r.Operator.OperatorID,
		Signature:   sig,
	}
	if err != nil {
		return errors.Wrap(err, "could not generate dkg SignedOutput")
	}

	r.OutputMsgs[r.Operator.OperatorID] = signedOuput
	if err := r.signAndBroadcastMsg(signedOuput, OutputMsgType); err != nil {
		return errors.Wrap(err, "could not broadcast Signed Keysign Output")
	}
	return nil
}

func (r *runner) prepareAndBroadcastKeyGenOutput() error {
	var (
		depositSig types.Signature
		err        error
	)
	if r.isResharing() {
		depositSig = nil
	} else {
		// reconstruct deposit data sig
		depositSig, err = r.reconstructDepositDataSignature()
		if err != nil {
			return errors.Wrap(err, "could not reconstruct deposit data sig")
		}
	}

	// encrypt Operator's share
	// TODO: this is encryped in such manner so that cli can generate a compatible
	// keyshares file
	// https://docs.ssv.network/developers/tools/ssv-key-distributor/ssv-keys-cli
	encryptedShare, err := r.config.Signer.Encrypt(r.Operator.EncryptionPubKey, []byte("0x"+r.KeygenOutcome.ProtocolOutput.Share.SerializeToHexStr()))
	if err != nil {
		return errors.Wrap(err, "could not encrypt share")
	}

	ret, err := r.generateSignedOutput(&Output{
		RequestID:            r.Identifier,
		EncryptedShare:       encryptedShare,
		SharePubKey:          r.KeygenOutcome.ProtocolOutput.Share.GetPublicKey().Serialize(),
		ValidatorPubKey:      r.KeygenOutcome.ProtocolOutput.ValidatorPK,
		DepositDataSignature: depositSig,
	})
	if err != nil {
		return errors.Wrap(err, "could not generate dkg SignedOutput")
	}

	r.OutputMsgs[r.Operator.OperatorID] = ret
	fmt.Println(r.Operator.OperatorID, "own output set")

	if err := r.signAndBroadcastMsg(ret, OutputMsgType); err != nil {
		return errors.Wrap(err, "could not broadcast SignedOutput")
	}
	return nil
}

func (r *runner) signAndBroadcastMsg(msg types.Encoder, msgType MsgType) error {
	data, err := msg.Encode()
	if err != nil {
		return err
	}
	signedMessage := &SignedMessage{
		Message: &Message{
			MsgType:    msgType,
			Identifier: r.Identifier,
			Data:       data,
		},
		Signer:    r.Operator.OperatorID,
		Signature: nil,
	}
	// GLNOTE: Should we use SignDKGOutput?
	sig, err := r.config.Signer.SignDKGOutput(signedMessage, r.Operator.EncryptionPrivateKey)
	if err != nil {
		return errors.Wrap(err, "failed to sign message")
	}
	signedMessage.Signature = sig
	if err = r.config.Network.BroadcastDKGMessage(signedMessage); err != nil {
		return errors.Wrap(err, "failed to broadcast message")
	}
	return nil
}

func (r *runner) reconstructDepositDataSignature() (types.Signature, error) {
	sigBytes := map[types.OperatorID][]byte{}
	for id, d := range r.DepositDataSignatures {
		if !bytes.Equal(r.DepositDataRoot, d.Root) {
			return nil, errors.New("PartialDepositData invalid: deposit data root mismatch")
		}
		sigBytes[id] = d.Signature
	}

	sig, err := types.ReconstructSignatures(sigBytes)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

func (r *runner) generateSignedOutput(o *Output) (*SignedOutput, error) {
	sig, err := r.config.Signer.SignDKGOutput(o, r.Operator.EncryptionPrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not sign output")
	}

	return &SignedOutput{
		Data:      o,
		Signer:    r.Operator.OperatorID,
		Signature: sig,
	}, nil
}

func (r *runner) isResharing() bool {
	return r.ReshareMsg != nil
}

func (r *runner) isKeySign() bool {
	return r.KeySign != nil
}
