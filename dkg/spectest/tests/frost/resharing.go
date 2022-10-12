package frost

import (
	"github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv-spec/types/testingutils"
)

func Resharing() *FrostSpecTest {
	return &FrostSpecTest{
		Name: "Simple Resharing",

		Threshold: 2,
		Operators: []types.OperatorID{5, 6, 7, 8},

		IsResharing:  true,
		OperatorsOld: []types.OperatorID{1, 2, 3, 4},
		OldKeygenOutcomes: testingutils.TestKeygenOutcome{
			ValidatorPK: "84d633334d8d615d6739d1f011f2c9b194601e38213937999868ed9b016cab8500e16319a2866ed853411ce1628e84b3",
			Share: map[uint32]string{
				1: "285a26f43b026b246ca0c33b34aaf90890c016d943a75456efbe00d4d0bdee01",
				2: "1d3701ab6e7b902bd482ac899ec7bab1852376ae234474bae1a3f83bb41dc48f",
				3: "42afa077e46dd25be4d7bb5be8734e77df5f074e0933f6ef6af8bdbe3e205cd0",
				4: "67c262ae06e14097b7b3e5a1a36526d6640ac899407bf61fd38c3490e43afed4",
			},
			OperatorPubKeys: map[uint32]string{
				1: "960498d1f66481d570b80c2cb6fbafa40a250f46510412eb51abaf1b62aa17e747c8c40f69d01606cd29dd0466f4a9a2",
				2: "a73f10841b40509f3a727a3311c77ee46ce0ae43ffdbd44aca87f837e392772834f51d1b38eacbe91d21057c0717a51b",
				3: "8982bd51c3a08d8eb0d470eeb57fe3a8a8db4f426026019bf27a5faa745fc13bc75e3e2bea2435f47fa9148313959000",
				4: "af4ce0c5ec16cc0d52acb5419d8b51051bcb271275680ab17c3a445d4de3c661971f19786667ab60216955bf20a13ea7",
			},
		},

		ExpectedOutcome: testingutils.TestKeygenOutcome{
			ValidatorPK: "93946df0d733b1dd62c3946522a4a77d4a326a58de930b690fc5b65e9873c2e1b5c5854157aa4f87e7fd0b6e120064bc",
			Share: map[uint32]string{
				5: "4f0e5d306131bf4cd73c68d6f3ba9c6222e92d514a36dfe0ec1c6d2639cd5303",
				6: "5b8e17de8d9403af83d004ddde93b544d0f84201b0a92adb2704eb7dded98844",
				7: "3a1db4e9bc49e01a51b3a7f1f6e4e6d874fd48ba51ffa222e215e631c7da1a5b",
				8: "34b8336303cfb48b781d7128cafccac130ce9688f6144491052858e4483bdc7d",
			},
			OperatorPubKeys: map[uint32]string{
				5: "a421fee84bf68927dbe73f6ca4294bc025209759ce4e56ffd4b5d15cf15e6bfc166b327078ad570664c52bec282bb4c3",
				6: "aded35f08c11c6a4e9e62c13a2e1095bfc0f88fa7f391d170f9037b43145446ddd18e90eb927979b2d56eb22de0a50be",
				7: "a40d75cb13c200007b924a2590d74feec49529c1a3e1afb2c00f67a2beb46f27b7fc0ab9f66b774957c3a0a67cb33a57",
				8: "ab6fa7c2f5db7ff70fa23e01f13804c019de9b270060b822ac54783df331ff23856d8957a18438914469f5cd8198ff0b",
			},
		},
		ExpectedError: "",
	}
}
