package frost

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

var (
	expectedFrostOutput = testingutils.TestKeygenOutcome{
		Share: map[uint32]string{
			1: "285a26f43b026b246ca0c33b34aaf90890c016d943a75456efbe00d4d0bdee01",
			2: "1d3701ab6e7b902bd482ac899ec7bab1852376ae234474bae1a3f83bb41dc48f",
			3: "42afa077e46dd25be4d7bb5be8734e77df5f074e0933f6ef6af8bdbe3e205cd0",
			4: "67c262ae06e14097b7b3e5a1a36526d6640ac899407bf61fd38c3490e43afed4",
		},
		ValidatorPK: "84d633334d8d615d6739d1f011f2c9b194601e38213937999868ed9b016cab8500e16319a2866ed853411ce1628e84b3",
		OperatorPubKeys: map[uint32]string{
			1: "960498d1f66481d570b80c2cb6fbafa40a250f46510412eb51abaf1b62aa17e747c8c40f69d01606cd29dd0466f4a9a2",
			2: "a73f10841b40509f3a727a3311c77ee46ce0ae43ffdbd44aca87f837e392772834f51d1b38eacbe91d21057c0717a51b",
			3: "8982bd51c3a08d8eb0d470eeb57fe3a8a8db4f426026019bf27a5faa745fc13bc75e3e2bea2435f47fa9148313959000",
			4: "af4ce0c5ec16cc0d52acb5419d8b51051bcb271275680ab17c3a445d4de3c661971f19786667ab60216955bf20a13ea7",
		},
	}
)

func TestFrostDKG(t *testing.T) {

	testingutils.ResetRandSeed()

	operators := []types.OperatorID{
		1, 2, 3, 4,
	}

	outputs, err := doFrostDKG(operators)
	if err != nil {
		t.Error(err)
	}

	for _, operatorID := range operators {
		output := outputs[uint32(operatorID)].KeyGenOutput

		require.Equal(t, expectedFrostOutput.ValidatorPK, hex.EncodeToString(output.ValidatorPK))
		require.Equal(t, expectedFrostOutput.Share[uint32(operatorID)], output.Share.SerializeToHexStr())
		for opID, publicKey := range output.OperatorPubKeys {
			require.Equal(t, expectedFrostOutput.OperatorPubKeys[uint32(opID)], publicKey.SerializeToHexStr())
		}
	}
}

var (
	expectedResharingOutput = testingutils.TestKeygenOutcome{
		Share: map[uint32]string{
			5: "4f0e5d306131bf4cd73c68d6f3ba9c6222e92d514a36dfe0ec1c6d2639cd5303",
			6: "5b8e17de8d9403af83d004ddde93b544d0f84201b0a92adb2704eb7dded98844",
			7: "3a1db4e9bc49e01a51b3a7f1f6e4e6d874fd48ba51ffa222e215e631c7da1a5b",
			8: "34b8336303cfb48b781d7128cafccac130ce9688f6144491052858e4483bdc7d",
		},
		ValidatorPK: "93946df0d733b1dd62c3946522a4a77d4a326a58de930b690fc5b65e9873c2e1b5c5854157aa4f87e7fd0b6e120064bc",
		OperatorPubKeys: map[uint32]string{
			5: "a421fee84bf68927dbe73f6ca4294bc025209759ce4e56ffd4b5d15cf15e6bfc166b327078ad570664c52bec282bb4c3",
			6: "aded35f08c11c6a4e9e62c13a2e1095bfc0f88fa7f391d170f9037b43145446ddd18e90eb927979b2d56eb22de0a50be",
			7: "a40d75cb13c200007b924a2590d74feec49529c1a3e1afb2c00f67a2beb46f27b7fc0ab9f66b774957c3a0a67cb33a57",
			8: "ab6fa7c2f5db7ff70fa23e01f13804c019de9b270060b822ac54783df331ff23856d8957a18438914469f5cd8198ff0b",
		},
	}
)

func TestResharing(t *testing.T) {

	testingutils.ResetRandSeed()

	threshold := uint64(2)

	// Prepare keygen output from old operators
	operatorsOld := []types.OperatorID{
		1, 2, 3, 4,
	}
	operatorsOldUint32 := types.OperatorList(operatorsOld).ToUint32List()

	outputFromOldOperators := expectedFrostOutput.ToKeygenOutcomeMap(threshold, operatorsOldUint32)

	requestID := testingutils.GetRandRequestID()

	operators := []types.OperatorID{
		5, 6, 7, 8,
	}
	allOperators := append(operators, operatorsOld...)

	dkgsigner := testingutils.NewTestingKeyManager()
	storage := testingutils.NewTestingStorage()
	network := testingutils.NewTestingNetwork()

	kgps := make(map[types.OperatorID]dkg.KeyGenProtocol)
	for _, operatorID := range operatorsOld {
		p := NewResharing(network, operatorID, requestID, dkgsigner, storage, outputFromOldOperators[uint32(operatorID)], operatorsOldUint32[:threshold+1])
		kgps[operatorID] = p
	}
	for _, operatorID := range operators {
		p := NewResharing(network, operatorID, requestID, dkgsigner, storage, nil, operatorsOldUint32[:threshold+1])
		kgps[operatorID] = p
	}

	initMsg := &dkg.Init{
		OperatorIDs: operators,
		Threshold:   uint16(threshold),
	}

	for _, operatorID := range allOperators {
		if err := kgps[operatorID].Start(initMsg); err != nil {
			t.Error(errors.Wrapf(err, "failed to start dkg protocol for operator %d", operatorID))
		}
	}

	rounds := []string{"round 1", "round 2", "keygen output"}

	outputs := make(map[uint32]*dkg.KeyGenOutcome)

	for _, round := range rounds {
		fmt.Printf("proceeding with %s\n", round)

		messages := network.BroadcastedMsgs
		network.BroadcastedMsgs = make([]*types.SSVMessage, 0)

		for _, msg := range messages {

			dkgMsg := &dkg.SignedMessage{}
			if err := dkgMsg.Decode(msg.Data); err != nil {
				t.Error(err)
			}

			for _, operatorID := range allOperators {
				if operatorID == dkgMsg.Signer {
					continue
				}

				finished, output, err := kgps[operatorID].ProcessMsg(dkgMsg)
				if err != nil {
					t.Errorf("test failed in round %s  for op %d by %d err: %v", round, operatorID, dkgMsg.Signer, err)
				}

				if finished && output != nil {
					outputs[uint32(operatorID)] = output
				}
			}
		}
	}

	for _, operatorID := range operators {
		output := outputs[uint32(operatorID)].KeyGenOutput

		require.Equal(t, expectedResharingOutput.ValidatorPK, hex.EncodeToString(output.ValidatorPK))
		require.Equal(t, expectedResharingOutput.Share[uint32(operatorID)], output.Share.SerializeToHexStr())
		for opID, publicKey := range output.OperatorPubKeys {
			require.Equal(t, expectedResharingOutput.OperatorPubKeys[uint32(opID)], publicKey.SerializeToHexStr())
		}
	}
}

func doFrostDKG(operators []types.OperatorID) (map[uint32]*dkg.KeyGenOutcome, error) {

	requestID := testingutils.GetRandRequestID()

	dkgsigner := testingutils.NewTestingKeyManager()
	storage := testingutils.NewTestingStorage()
	network := testingutils.NewTestingNetwork()

	kgps := make(map[types.OperatorID]dkg.KeyGenProtocol)
	for _, operatorID := range operators {
		p := New(network, operatorID, requestID, dkgsigner, storage)
		kgps[operatorID] = p
	}

	threshold := 2
	outputs := make(map[uint32]*dkg.KeyGenOutcome)

	// preparation round
	initMsg := &dkg.Init{
		OperatorIDs: operators,
		Threshold:   uint16(threshold),
	}

	for _, operatorID := range operators {
		if err := kgps[operatorID].Start(initMsg); err != nil {
			return nil, errors.Wrapf(err, "failed to start dkg protocol for operator %d", operatorID)
		}
	}

	rounds := []string{"round 1", "round 2", "keygen output"}

	for _, round := range rounds {
		fmt.Printf("proceeding with %s\n", round)

		messages := network.BroadcastedMsgs
		network.BroadcastedMsgs = make([]*types.SSVMessage, 0)

		for _, msg := range messages {
			dkgMsg := &dkg.SignedMessage{}
			if err := dkgMsg.Decode(msg.Data); err != nil {
				return nil, err
			}

			for _, operatorID := range operators {
				if operatorID == dkgMsg.Signer {
					continue
				}

				finished, output, err := kgps[operatorID].ProcessMsg(dkgMsg)
				if err != nil {
					return nil, err
				}

				if finished {
					outputs[uint32(operatorID)] = output
				}
			}
		}
	}
	return outputs, nil
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
