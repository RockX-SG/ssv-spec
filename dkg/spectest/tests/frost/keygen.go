package frost

import "github.com/bloxapp/ssv-spec/types"

func Keygen() *FrostSpecTest {
	return &FrostSpecTest{
		Threshold: 2,
		Operators: []types.OperatorID{1, 2, 3, 4},
		ExpectedOutcome: struct {
			ValidatorPK     string
			Share           map[uint32]string
			OperatorPubKeys map[uint32]string
		}{
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
		ExpectedError: "",
	}
}
