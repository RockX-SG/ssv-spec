package frost

import (
	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
)

func BlameTypeInvalidShare() *FrostSpecTest {

	requestID := testingutils.GetRandRequestID()
	ks := testingutils.Testing4SharesSet()

	threshold := 2
	operators := []types.OperatorID{1, 2, 3, 4}

	initMessages := make(map[uint32][]*dkg.SignedMessage)
	initMsgBytes := testingutils.InitMessageDataBytes(
		operators,
		uint16(threshold),
		testingutils.TestingWithdrawalCredentials,
		testingutils.TestingForkVersion,
	)
	for _, operatorID := range operators {
		initMessages[uint32(operatorID)] = []*dkg.SignedMessage{
			testingutils.SignDKGMsg(ks.DKGOperators[operatorID].SK, operatorID, &dkg.Message{
				MsgType:    dkg.InitMsgType,
				Identifier: requestID,
				Data:       initMsgBytes,
			}),
		}
	}

	pmData := `{"round":2,"round1":{"Commitment":["qzHrRAIpma7lmbbm37SazNCYX6WE2/RYQF+lQdr+s+SO/3AknLoMH0ocuAFjx+Fa","luG8uPgVeTmvRoE4MBPMpt/Vgp/oCAA9TBTzG07bRJ45L6Uo9uDGQ9gKFkt9+07n","kBb0Obbc/CYaBH/56rZtOUw6bz6DMFrbouRUNwh8lBfH8OjWg3NQwBIXE3Ir8lmn","p7CN+Aow0TPzKW0wFmbL3qNYuSnjLEo3Gtjapg71mDYn9+IGpmGtoqHAd1LUzxDA"],"ProofS":"YI5p9V013jgYX/78TJ3PSdI/5QEbZFKnRND0pTo6XAE=","ProofR":"MW4+TKI7AAf/q0OljiJiNLSkoAPXy4PzTXC2dFqhlAc=","Shares":{"1":"BLh2p4b+/slitPiMXooPEka+S6TqCcdQSB7Bzv1XTZNp0N5wpnI/jgA4qAwzg2YCbVdBzcG26FF5p/4FRHk1syDz0ljuJkv30ahpxt/bby1ItMnBKgy7p+zYOE9RkAlecpnowYohR3wj/Fxq/ln5gNRWDmMcWMePrflm5dpMCziY","3":"BMqwinOzpjBtLed3b/pCDuG2x9XQPzXlKIXHtR+8pK4R+qPbU6hB4Xgf/9D/b2PKs/jnH6XOKfLX7q1bC9DZkH59cmeeeAHFjy3YeObXyF3L7E1MX4NWHxmkjjWSLiH08M2MkQCtfrswWzIfOVT7YgFJSRRDy2sf94CA1WdbFAc3","4":"BKLu/3DyaZOIzXx6SkKrRhxojh30Y5uLXOqBGbt5hQiPZpbDtULBSdTr4XrUyXLdmi3JW+jiZihksHxHjZWgq7mdlhMspFYyEnqxmobMBuDxydmEa5VzdoCtsSrRc79kx9SkwMsNkmY52VhtkgwLlISCXSdmAQc8BIn3kT7xQcy1"}}}`

	blameProtocolMessageBytes := []byte(pmData)
	blameSignedMessage := &dkg.SignedMessage{
		Message: &dkg.Message{
			MsgType:    dkg.ProtocolMsgType,
			Identifier: requestID,
			Data:       blameProtocolMessageBytes,
		},
		Signer: 2,
	}
	sig, _ := testingutils.NewTestingKeyManager().SignDKGOutput(blameSignedMessage, ks.DKGOperators[2].ETHAddress)
	blameSignedMessage.Signature = sig

	return &FrostSpecTest{
		Name:   "Blame Type Invalid Share - Happy Flow",
		Keyset: ks,

		RequestID: requestID,
		Threshold: uint64(threshold),
		Operators: operators,

		ExpectedOutcome: testingutils.TestOutcome{
			BlameOutcome: testingutils.TestBlameOutcome{
				Valid: true,
			},
		},
		ExpectedError: "",

		InputMessages: map[int]MessagesForNodes{
			0: initMessages,
			2: {
				2: []*dkg.SignedMessage{blameSignedMessage},
			},
		},
	}
}
