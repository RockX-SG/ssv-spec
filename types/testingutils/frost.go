package testingutils

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"math/big"
	mrand "math/rand"

	"github.com/bloxapp/ssv-spec/dkg"
	"github.com/bloxapp/ssv-spec/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"
)

// Keygen
var (
	SessionPKs map[types.OperatorID]string = map[types.OperatorID]string{
		1: "036ff75a45bb43f1190f89838326ed4f2e090293184e56ff4a01a1a6db548fbae6",
		2: "038680ce08d663c436ddb98265dd26a0c775bf4728ab5ae385671eeb5b87ab08e7",
		3: "0204470b016f243d34ff27d8c869c3b8012612232390d8d3259bc40bf4dc3c4551",
		4: "0328893f709ce7ad1ee70f393cf5ba152fc11043043f0a0acb1591923ebea52dbd",
	}

	Round1 = map[types.OperatorID]struct {
		Commitments []string
		Shares      map[uint32]string
		ProofS      string
		ProofR      string
	}{
		1: {
			Commitments: []string{
				"b1fc06dbfe90a494bbda98ce51663eeec74134b3faf1f667f872ffff9b7a7747e31fab29b8d2d7e30e5b8dfe26f4d552",
				"821696e875f72e1b85be294972c02787f839626077298791c4e7c553c6762433c2b7cfeba151752316ca926fa9ba236c",
				"8f66b1662e494ad37239040812743d7d68e256f57a59beb310c93e2df17b41e51d534168a0abc93ebb56785524f0586a",
			},
			ProofS: "65e597c5000b9b6cc2953b7c44b93e5ca5511f7c2cd81c7680bede9bbb9828b6",
			ProofR: "4429058e0da3ca520b3d311dd9eae36c132151f99c804278f59eb3ddc128407e",
			Shares: map[uint32]string{
				2: "042a60c3ef5efbcc802221c346ac73e997c449a66ecb9dbe4f63108c67678e62af7e151cc8b8289d1abb43ce49361490ed889778d44d6cb623ae169c300881d6124cb9ce563eaa36f0b96eac28a033e582f35a7eca9d0b73d585428a647f6614e42b54946930066fcfb71d4c767b85b1b146e6cedc5ad5f743b1c8080f776460e6",
				3: "04ce72a9cb7c24930acc3ee568e9999254d425e99e71d72e0500dd81d1818ea303ae8b7b0c075420403a9a7c3f5ebe8b2df2e702601aa49932b5b771b14b2bb3a0730dc4c7f9c1422f14b7198361b631e1e04c89301dca6796bc4b417c5888e1820b2906d96571550425655c101a16357be1bc2c162ca7ba0062fe4890fddae895",
				4: "0446fe513897e4ba460aeefc76c5e8ac2f60f7fd0e93797c406c93dbca02fd7f55e79e9b322b9641b1a77d11adf4f38feb132270b3d28463c5e3be517c1d80ae4a5d262ab28924fd6187cde8490979e7a0e3ff7896ea7fb9a17bd6095e4afe913967655f9a00999f9fbd7c16e262a3686802b2817e5ca216aa2029c420042e5fd1",
			},
		},
		2: {
			Commitments: []string{
				"af8a4e775d7d80b5f3b74eb1c2f997b9d218ac414797b6724fbc970cccf75adfc298af8a90f45e9ba9eae28bf949fdea",
				"81087c05df25266a244fdcf31542bf8dabd6a7ccfc54e229e51fe40b25f10a862aa480b23b09a0d1755864c2f0223fd0",
				"ab31eb44022999aee599b6e6dfb49accd0985fa584dbf458405fa541dafeb3e48eff70249cba0c1f4a1cb80163c7e15a",
			},
			ProofS: "458e8c8e76a908fb6de9c47d61759d6dd77731ef014890ab9532695fdcb96cbf",
			ProofR: "34044356f2931faa528e262d33052a899498bf594a35593a75e0c1f4571d7640",
			Shares: map[uint32]string{
				1: "04e483c6b63c6e6c0ef9677062cfd38030bebe25c2610aa574da04992bad387ae58c1a081a64bd28a9b16c0604a5d4ed93e6a1cb23a71b49479f7593acdf4f24479813a42970682b4645163aafd14b01d05f9d11d348949829d71f907759551dc934c03b392f7a77d6aeae96fae550e15bb4d24e7dd16f7109b06fb4633851727e",
				3: "04e94fa027890da52caf76d15463e5534259d4e80f9bc4ad6c0f770d8c8468be5ee58ecf3731320a7ac33d656856a9cd6cf93a1a29161e819dfec389081e25edf062c9dd07d07e98a70cf8e0c16112ef2a8015b1146786ef7d0764abf8fba9a3d38f137e48f597eb531dda88f0edc68f3c160f9d543a5d5a215ebcb30b2542a78b",
				4: "04765affeae2264ce133b3c5908173865524a97d8adcfd624193b5c094539b2bcfbaaa989c07342ac6e44a70d2abb193c300392fe8ed95edd8e0d9715451f996af51627b703670f2465883c33c62b3cc6544342dae70057c8c92c3eac325aedc9715944dabcc8c77846b00d662ff4c20a6cf21dd00c2b9573116fba72703328016",
			},
		},
		3: {
			Commitments: []string{
				"a2e4badfdc21372375a741669676f51bfea8a9e21dbd16286217d5931f690c8aa9c06bf0138c648d61b1acee7bb68198",
				"8deb67f209dc09235c4627f750b2a95ace958f97baafcd95560517f39e4a0d3bec31cddb1fc52f9769c3df44d15e8a63",
				"87addd83d2a222ca610102e401da2a2070d18c32ca1b089cdc683f45c3149fbeea3312451d2c658ff41ea5330e98319e",
			},
			ProofS: "455bfc61aff5b8f90eb32a2444ed72fac45cf69533ac2d343b9beac2ac8eb08e",
			ProofR: "018330f5d32492fbc2a3e65dd80c33f63122d743affff9133cbf448b66f3d5a1",
			Shares: map[uint32]string{
				1: "04a93822a49b25a5f0c2694596cb0f307ed0eefb35ada9f749b827df128a2155bbdfd027e225513acab4a8acfbcd329c41cf6c00def8c37b10ca0d7be25a92fcc19b872a79069f1a6515e66a893fe6e0c59b1cea6fd93dba3bf900d22290defd68c6a4c9794ab054147ad48fa3edb0ee63cfe649164d1eec46e110436b86fa6f4a",
				2: "045234ca3f8e31bf2cc0f0350c68db67ea16a3cf9f1ac439dbefa486ea5c003592d8b057b8370237bd7560ac84b02c9c0d6bf90352c2fd482aa68282a16b88f05aad6900642af14353a88b7464410803468dbebe83e611c84a74f22226355ab39ed86f90a5ba76620fdffaae9b00b64b14293a7f09a323b5b2fcc127832b599662",
				4: "04757e324022b39f7b27ef4d32dc38d09978623bbfc4ed121529e67e3f3a684ae5f8b3cdcbb983767fdd3d26b6f714cb349d81ff8d8b3b5fbb659b4d03234c94d878501438f98e3ed493250693624397a3ca7ef827c9285b4a4af1b56f321f52cd59f825dcd5db095875b23c420f25cea6928d2cdfdfb53f25b96219ebd63726d7",
			},
		},
		4: {
			Commitments: []string{
				"a764e878ade532a2ec3fa8f8813fddd2f33a3318ec2652354d41d90e198f3c17b4b8735d4d5984c5f5df650d082d78c9",
				"95146fe1402bce6dd575e313294d7b02ef5d79eeaeb26ce3da3e02eb93d93a46a7b4fe1db0c842b3e2de8503c0c47e28",
				"967597e453bb617e77dd2341c3ace40a1beb4795962c720c67fec55bfba4ae628b2171b33ab3ea2148c6c287a97e0b34",
			},
			ProofS: "259cf2af7c9662ad2415889901c368ec25aa4abf177b8c01d82635c85ef7cc41",
			ProofR: "498842cfe23f756abb34b50cf866126ebf68aac5af49b28860eca15ea9768be7",
			Shares: map[uint32]string{
				1: "0446fe513897e4ba460aeefc76c5e8ac2f60f7fd0e93797c406c93dbca02fd7f55e79e9b322b9641b1a77d11adf4f38feb132270b3d28463c5e3be517c1d80ae4a5d262ab28924fd6187cde8490979e7a0fee327110c77430f348c8aaaa8dda7dfccc0bf452f7998aca584f2a5e2ca43b2996603124a3f50e12ca6c128199e1543",
				2: "041270eb0c929301038afac519236be54fa97f0a428c2d73b46cefc89e198eb8b0058ae7b1ab2a5a778d873b88d07eb44aa944ccf9397672b9078c83f4c7c0bf2ab5d2f8c17070fc16e3d796ccc5cc29becc2e9b260461383ec4a789a6273ed37ac61247539c72fb11f4ea954e9080b98d34e5b9e60d4b208af59d1239dafb81dc",
				3: "04ca7e6fb4b57c8d847cc30f943045f970bb2b0ecfd926ac7d4275dfccb53c62a3eedd9ab9091699992f4073d9daea3dccde2b239e7be5a2f9e42a8601ac21ad1b9be9b36d34d09c5c22eee19a2957436c52b960f37e77a8d8bf184296ab6d7b637776914aaf9e67f02f26bfbb674aaac2ea7419582fe6df68bf7e6ec4a1e163e4",
			},
		},
	}

	Round2 = map[types.OperatorID]struct {
		Vk      string
		Sk      string
		VkShare string
		SkShare string
	}{
		1: {

			Vk:      "871ac12101b6a8dc6edac502d776a10c01fceedf727b10acb40c6f9de0c977c63879ccb895db7d92ad3d4e77144b64ac",
			Sk:      "65f80c8ae56d2385612e206d53a3db6083b86ffb7ea093ddcf40cb003a60014f",
			VkShare: "a20f5933a6a97e7cd2a0ea65e8e55493bccc60031065429dc1184d72bbbb916491da73cc649760b3d739647077944236",
			SkShare: "6c190c998b847e71713336f884badd4b10ba7cfb488e8bb6c2c95e92c6406a0a",
		},
		2: {

			Vk:      "871ac12101b6a8dc6edac502d776a10c01fceedf727b10acb40c6f9de0c977c63879ccb895db7d92ad3d4e77144b64ac",
			Sk:      "65f80c8ae56d2385612e206d53a3db6083b86ffb7ea093ddcf40cb003a60014f",
			VkShare: "8412c202a39d5b68f3e56c34d6ec721d69f9ef9fc12560c76bc53b1a07118f79ce70850c3f0773b45cdf996270c8b52d",
			SkShare: "64425aa3e6d73fae40f81c2a761503a86ccfc3faaef47e3dc3b00f1513fb1ffd",
		},
		3: {

			Vk:      "871ac12101b6a8dc6edac502d776a10c01fceedf727b10acb40c6f9de0c977c63879ccb895db7d92ad3d4e77144b64ac",
			Sk:      "65f80c8ae56d2385612e206d53a3db6083b86ffb7ea093ddcf40cb003a60014f",
			VkShare: "8a819950175eb638494ac7a037362469f8716d13800a58cb2109b8a7b128ff6f3fbf5fe2b507377d41dee71bf2d906f3",
			SkShare: "4e73f6a9f765673bd07cd00327b24e7897f844f9b1d26b72d1f4dc8723902328",
		},
		4: {

			Vk:      "871ac12101b6a8dc6edac502d776a10c01fceedf727b10acb40c6f9de0c977c63879ccb895db7d92ad3d4e77144b64ac",
			Sk:      "65f80c8ae56d2385612e206d53a3db6083b86ffb7ea093ddcf40cb003a60014f",
			VkShare: "925aeda7183eecdc8e9d27ebc32a32bfad15683a36cb2bfa3ca5f450ad92917d46a35a2d4b66dd976defd0ba6306e78e",
			SkShare: "2aade0abbd2ef51a1fc152829992bdbb9233fff851285355ed97c6e8f4ff738b",
		},
	}
)

// Resharing
var (
	Resharing_SessionPKs map[types.OperatorID]string = map[types.OperatorID]string{
		5: "036ff75a45bb43f1190f89838326ed4f2e090293184e56ff4a01a1a6db548fbae6",
		6: "038680ce08d663c436ddb98265dd26a0c775bf4728ab5ae385671eeb5b87ab08e7",
		7: "0204470b016f243d34ff27d8c869c3b8012612232390d8d3259bc40bf4dc3c4551",
		8: "0328893f709ce7ad1ee70f393cf5ba152fc11043043f0a0acb1591923ebea52dbd",
	}

	Resharing_SessionSKs map[types.OperatorID]string = map[types.OperatorID]string{
		5: "1aab69564b34a33ecd1af05fe6923d6de71870997d38ef60155c325957214c42",
		6: "59954b863e2fba93aeceb05d2fdcde0c9688d21d95aa7bedefc7f31b35731a3d",
		7: "293411a6b583a5c30587d4e530c948f013e96d5a4e653f0791899d6270c6f3c0",
		8: "4f87fda0de889c645b07fce5df52984808d3c3e2f1ea1b5217e499d56e963fc9",
	}

	Resharing_Round1 = map[types.OperatorID]struct {
		Commitments []string
		Shares      map[uint32]string
		ProofS      string
		ProofR      string
	}{
		1: {
			Commitments: []string{
				"ad6c84632250ec9a0d69d17883eb99ea7819662026816a4d71b72ac2be0a94d2e5ac81fb82f1e6e5571db54616cb2678",
				"a764e878ade532a2ec3fa8f8813fddd2f33a3318ec2652354d41d90e198f3c17b4b8735d4d5984c5f5df650d082d78c9",
				"95146fe1402bce6dd575e313294d7b02ef5d79eeaeb26ce3da3e02eb93d93a46a7b4fe1db0c842b3e2de8503c0c47e28",
			},
			ProofS: "2095e190b188e494e34aa72b66ac4cfe3387d620aaa638cec1d7a14e71408d8d",
			ProofR: "6803dae1e4f06ddd55a2a4858970602ea86f36ad3d3a1743fc799f93fa7f2ce4",
			Shares: map[uint32]string{
				5: "04d43ea927cacffe0aec6094a9d093530390d5d240121faad3be931c673b368d9727a6bbb07870a0705669a890b28d0d4ba97b597f3d9ddb37006a1e06af23708d7847a42ee6d7af1316c229404853a3d6aad8e8996f5fd1804b549778883e91d919ad65b30979a5dc0e09cbc4ebd0f4549f737360c56a020fbe50db9543569115",
				6: "044ed564bffa09d8f4d4623eb7716259037086a65dfd9a24eed099fd291872bdf3deba2c8df42876c9aa99e4a353d33c257a864d936f8f7230f130679d928c1d53903721f578b7b4986da0a0aa6cbed4806ba987474d3b8fbd6dc813bb83748f710aca9f4583243f9733592e9746c0d13eb5bad92272a2c013e9c915a830acc866",
				7: "04a3616797f292c658ef6dd57d3775ab9417102d2d66ef541d185788d7da351e34e0390c26e62f14ff2063b964216854a8cd671291d494b84583236d40ab24396b10a79af3b20d42d44a4d45148e3a9691e89f1886c1ed6f87bccff4b2bf3e1cd44d3bcf22885e6fa5e584fb52266a77bda31052c61d0dcb45153bb1686be9e274",
				8: "047fb4f7a3bff36c1afcb73f553f449182f0bea4186066c446d2b76a49e192a9408eda1dfabe5102f0df3e9cae90d65d81253ca9ac33f532456b0e43fefe33ff20e575e2b3595459206962df497e4aa2c2b1f106d8dc778ef24f0bec6d1a459ec60590672d9408832dd562e2d008c7dbc872e69e8b768bafeda64c896bc49f2123",
			},
		},
		2: {
			Commitments: []string{
				"93580f78cea8d29c17418ea11bc0a9f8bf22f05a0166b3b35847a04eb882340dc8cb8e4c251a2b9811344044bb6e9248",
				"b0799c7e34937bc5be65a80756d67326dd19e39c896f26e16a1324726a279c92e6a59c32bca417ec6e2c6a110ce4544c",
				"9782cfffcc88e758fa4784027f63fefeb6f8a38e15792358158ade28d4993da519470fa80b7478570e519a5e5ef5eb88",
			},
			ProofS: "17d076cc2ad7fd1d82deeb539bb45bc8fd053da506313a2984b9f766c10bdecb",
			ProofR: "3e5c77676ec03d4ccc814f5d1771d06c74b13b26ffcaac97bc83dcf63689d5f5",
			Shares: map[uint32]string{
				5: "04b4317d8d0da8ed1880c9e75a8e5d00912d905c47e26c1550dac93ae587dc97ec89cb01aa12e67982550bbeb531939e23a07cc8efdf7dda75887769d27d79a35ae1837f400e06183c8601fbd74c1240d2f3112e5ee04159a9b1ca115876e123ede66bee95dfc6eef126bb68a80141485ed2e0dd1d42c2ba0838bb4482bdf65ea8",
				6: "04385be66d74ded68c0007df6f372af21dbc210b6026a2f2f60065b89d0877e7361566b2d25c3df4fc4a7e28097ce28e4fbb50b0165b4a785a81d9653a788518246be65deb2d25245e97e514036d8bc5973d54118655a10849db4839bddfefd43c1677d33cd77307e9b353720a14630c6763126f9322926bb9b18d8235801e712c",
				7: "04cb029518729f4554b2f0465edff505f4140505ec12b09c2a507794284d415162ecc14ad2d0de84287b2eef0f1bc5a3db9866c79992e6ad56294312c330fae557e27a059102059e9f83d40624c333f85b4a5197e62350fafec4e7f42e775fd20a350b4c0f2adfbc6f656c77173a8025dd2a3eef9455fd6422e13426a8436f3c36",
				8: "042667c901f799f294ce200f0787e43385544de0d4058d0d8b63bad5005708248e6e0ea2175e24bcb9553a93f9ca4ab0377dcfc224a10529527deb0080600cc0821f900469bacc0b261406bf773d73812f02b5ab2caa59e1efc2e02f28874388a43e32afee3a6869b534732df09fc41be2b68cf795890de819e50ad921fa45dcf9",
			},
		},
		3: {
			Commitments: []string{
				"8a819950175eb638494ac7a037362469f8716d13800a58cb2109b8a7b128ff6f3fbf5fe2b507377d41dee71bf2d906f3",
				"8bd6a423f76651c8ad06f5a63e9e6a76e0971a10a12f95077bfd916335857cbd03ac5a384668b175861247cff8bf114f",
				"80561e460504885ffaa2a83e3e492583243790475ab10a6fa49a5e225bec5936ebe56d122e3f96b5b8d730737e52440a",
			},
			ProofS: "68ffeb968eb85d9b4ba0a7d00185130eac466c73a13d6ed38cf0e48e0cc2eb2c",
			ProofR: "1b7eff48275dec08527b5636dc5fd713c36e0cc943cd25e77899c74516dc7d82",
			Shares: map[uint32]string{
				5: "043cb36d672046a0bb2932dceb5b3189358005d50387eea3b40d8cbf2b051153e9817221cf898b06e7b193d8418abe6b6c6f34ae8f5640442563a0641e3ce8a901b2a4e6e935d42add6d2ab3c0fb1aa9e22062eb493f1ac95ec0bfc30cc8831358fa4f11938515bfeffe59d0d4861b68a825b666afa7205a2c5a1f8afd70a9b7d5",
				6: "04a5e11e9611e90cf06b94632322875c1cf14fb52cc8d22bc1c0e8242afa81d7a9a35cfbae04e82f2f2cfeb35d7cd7d583293b17e4ac61f11dd418728a36390486ab613292477efdad3d8043b562a9f762677a1866ae9d506d7410277999b5a2733ce18fa0075a37b658c89c9552a6bc1564d9cd2c9aac06bc89cf27634fc48ed8",
				7: "04e483c6b63c6e6c0ef9677062cfd38030bebe25c2610aa574da04992bad387ae58c1a081a64bd28a9b16c0604a5d4ed93e6a1cb23a71b49479f7593acdf4f24479813a42970682b4645163aafd14b01d0172e22a3b228312b114f042c68f8eefaf5087230ace0cf48b5ccaf852bf6a60e09ab4bea21d96cddf84c4d73186c8a45",
				8: "04e94fa027890da52caf76d15463e5534259d4e80f9bc4ad6c0f770d8c8468be5ee58ecf3731320a7ac33d656856a9cd6cf93a1a29161e819dfec389081e25edf062c9dd07d07e98a70cf8e0c16112ef2a72ba2a93b97a617da4ec37e22db87adaac9b0ac8a0cb24650e399f0e4d45eded1e1c8e10209bd485849705572d8d6675",
			},
		},
	}

	Resharing_Round2 = map[types.OperatorID]struct {
		Vk      string
		Sk      string
		VkShare string
		SkShare string
	}{
		5: {

			Vk:      "871ac12101b6a8dc6edac502d776a10c01fceedf727b10acb40c6f9de0c977c63879ccb895db7d92ad3d4e77144b64ac",
			Sk:      "",
			VkShare: "933e2a65ce75eeb769781d080d7f7698a202d342548e4bac6a2fa7355622dba4c06d22a7b84013e517f37e31f88e5e11",
			SkShare: "73484ee28ff0de485ae0256347d526ebc6518a32d6bfb21f905e96d97228fd76",
		},
		6: {

			Vk:      "871ac12101b6a8dc6edac502d776a10c01fceedf727b10acb40c6f9de0c977c63879ccb895db7d92ad3d4e77144b64ac",
			Sk:      "",
			VkShare: "8b1f46d53862cb0a5722c67878a02a4bc6602befdd02a875512dfe27562b39a9c195d2d0e390a4ad13f9568ac619e07a",
			SkShare: "30616227ac07478aa645c63da8c462a296eb88651ba5dbd0872926107dfa2e10",
		},
		7: {

			Vk:      "871ac12101b6a8dc6edac502d776a10c01fceedf727b10acb40c6f9de0c977c63879ccb895db7d92ad3d4e77144b64ac",
			Sk:      "",
			VkShare: "b2a7448a4cc5bd127fccb8155d6704bf7a7d12a711692c55e353e0c87f7430c60ba0b5748641dee6127a6b5e163e1a41",
			SkShare: "427d68edb9c06f90e5b321be55ec76d64c1b61962d5dab83f68a932856d08031",
		},
		8: {

			Vk:      "871ac12101b6a8dc6edac502d776a10c01fceedf727b10acb40c6f9de0c977c63879ccb895db7d92ad3d4e77144b64ac",
			Sk:      "",
			VkShare: "909357080a87d6a3cd749b5d3e4824d3a62b009039197081e4ff07bd60763140e0a212c4b05451ff2b46d98ee185937c",
			SkShare: "35aebbe18f7ed912e5ee5fdd45ab8b81922371c30be8c53ade82de21fcabf3d8",
		},
	}
)

func TestingResharingKeySet() *TestKeySet {
	return &TestKeySet{
		ValidatorSK: skFromHex("65f80c8ae56d2385612e206d53a3db6083b86ffb7ea093ddcf40cb003a60014f"),
		ValidatorPK: pkFromHex("871ac12101b6a8dc6edac502d776a10c01fceedf727b10acb40c6f9de0c977c63879ccb895db7d92ad3d4e77144b64ac"),
		ShareCount:  4,
		Threshold:   3,
		Shares: map[types.OperatorID]*bls.SecretKey{
			1: skFromHex("37a822a012706efb37521c42a6e3efd8a1efb66e0060eb473785f92539fbedb8"),
			2: skFromHex("1000b6658c8f62cafd41ac89321ab498a0b5986e39099c248e3e171e170379c9"),
			3: skFromHex("62020e335b03f3ec3734868dbd072256f8fdb1859e5c9e74d039e8bf0f031aaf"),
			4: skFromHex("73d8d8e7ed8d454d980636e29d7d7ad654ba2021cc0585e3cef540523fde1ff6"),
			5: skFromHex("60bc0a6cf4afeb553d9e319928ba3ff722b97610103d9a76addd5bf299adf2a1"),
			6: skFromHex("6b3fb8aebce28a51ed6b7f4c5481f2833fb429b0fd2cb7df5f40e7bbb3dfc228"),
			7: skFromHex("26cca03eaf459be04d0a4e5ee3bda0824a85de69eaefbc4041af0e1aad46ca82"),
			8: skFromHex("2fce3c93f1974af54a6e789d585f53369a045c666a3aae59ddc5963a17233341"),
		},
		DKGOperators: map[types.OperatorID]struct {
			SK            *ecdsa.PrivateKey
			ETHAddress    common.Address
			EncryptionKey *rsa.PrivateKey
		}{
			1: {
				SK:            ecdsaSKFromHex("96e85c616d446272f387f52f8ce936ee7ac3c65ebe284d1de3c481fa0d147501"),
				ETHAddress:    ethAddressFromHex("535953b5a6040074948cf185eaa7d2abbd66808f"),
				EncryptionKey: rsaSKFromHex("308204a50201000282010100cd2476cbe0327a3d7042206e11b549e9519cf713c2fad9d7f9b6e7625c12d69eb5f8ad354ab1af7b4a5b96684802d28e0123f0a25240954821884b516b1bb368b1b8f721ec49e7471cfcc4d7430f3109eb23941a51e6fe172615c0bed0395b41a7d09830fbe67fd38276405caa064fd6e9f3d3a4989be64fcef96d81e28aba5f078376bc4301610ee4c7532c96f7eaf5c403aaa1ed3ac7d779075f64d37ff261e60717825becb181d042ef2e4642cc8ee330d6812c0d98447e8221dacfd839693a0c368379581f5677f64ce45ceeee98b678e8cdd4caf03428d6063ddd298da55ddd5430735b1da21ca38b1922c04622129e7ac925c03546cc39b3b690951c350203010001028201002df4422c6f9fbf246e3651ff76360f459603bc918fb713ffbeafcb6b8c46a80f4ba25662bec5c912ac5891fbf04db98f18104e027ebc7af47a968690c9969dfd10fae759910e0922340b27a9351b7d17c4b5e6a272c0752108660d14719eb7a3a08d28daa8433d554b3f64319de0e617b5b6ea2d5006747462601bb8e1dfc3d9c92309cc0fd8a576723ae6aa8d8dfbba4872067ecf644c4730c00b00a2b8edd1789e0a0ed5e3b76b5f2d31db12105120e49aaad8eb4a5dabc62adfd0e5368773548538ea66c87ea576d7b7a20a8738c25cb1347e5d0bd1cfe28633faaed97d9c070622ddc3764c00e9ce00fc8325b7d5109e543f606d47cf2d953436099f976102818100ec784008ff79151521baa6b98f32c923efae24ce210a51ecf50874332624fe3c9edaa71698a0c7c99273f7d1759785799aa9649e0e62de74586bc768402a6c30ea7c0a949357ba17e2f52c1d92ad3a069a7bc7c5818ed2a7e0ebc5de7ac2e0f7e5b39dcd5bfa0916f3b42fd3316e1556f5617bd50c09a49f0d819e874d4df60902818100de15da091d66d42da949cb3c6dff2d3818ed86ca0d5105ae063ff705b45f6cfb04f4592dceef66d0975b8bfec6abace5a6124f2d22bc7a568f542b67b6f0d6579c9332b912f98482b82347a1a9adc72a97a9c1d05761bb07fe806a1a3f66a62a158d0e4a918723611627ff4808677fe4cab31eb1e55ab33e46b0a870ac7c1fcd02818100bbdc387b2d82a3161baaae43a298e524d08817a34eaa65358be1007796293375337a5fdddab9789f11e361909d0c1834e883047570d66906232cd4c964988f453933fc2fd6f28ddbe62982b7a7cc48d9f026c0298f68c8c0283707065d9eae9d227654ba4e04d0edd404652e3209d39836ef1032cc12691f16dacff78b99910902818100c67752b54890275772ecde71ef7ed62346aba60414e86e21f9b5da04400ff32d545d2500f9e819c2993097a82455311abd51a96e1597c7e0690ff80624878f9515f8b9a0892370d6fcc59273175694212d0de8854e41a949d8975bba7f2435a47043f11c9476e718111bc757d122e5394a27ce6b7e229302395c0ffb393967950281810094163aa0f45111ebb0539c52d35287b08e2aae25d62ce815e2ca6804689c33949420d7968dba1674aad76b8c501940a5ac32e4574dfe6511adf8ed8e6d6b25ceb2037d3b6bcf5ec11b0b3d0eae638e21796d042473fc8c0ee2a8d480b3053c2069618f1dd551e1a1d8c76327efdc704272e8cedba1e1e51f82308b834ed692f4"),
			},
			2: {
				SK:            ecdsaSKFromHex("6222880ea97bba45d6120626691bc74829741db4ad9300a85a20a925e2c74996"),
				ETHAddress:    ethAddressFromHex("01139beb7ceb4c6a9fd3da779ed69612e489f4e6"),
				EncryptionKey: rsaSKFromHex("308204a50201000282010100c0a177fe5c06b91d0374b66a69a6dda067439085de6248825aebcea570873abecb89f8bbb52aacaebf80d46ee576593f10d804a6ffda4274d6fc19cd2444db74c690adafc2432f13149251e5624d8dd32f6fe034d9a174605105ee5d3f6285a220657cbc1d8f52abf6789eef8be2ab831a9f66c9556a43a10d3064de8f9924ccd818966502ad75079006a267116f5d328871f9040c425b4fb4f3d33985fcfd161ac4fe8e8e7b13205208ff13b353f4a56d394e0b08d1b770ae6f3ad8242c2401433eecf3f0a0fc0e2fe076e21041525c7bd27bd659bc386067d5bd2fa88fd6ca8f89092d598c99f146b996a6ce4667cc4be7fa9c9013ffac90e4b82cb075d95102030100010282010100b85b50be0d5119e51ca39cd9a717de505fc4181326cca55cacabb5f03c0c103afe0da411f1c74fd146d2837d46fac75b464197e244479d06b9a239074e48e04798aa6ab02599aaf9f5dc3ba8ef360e2029ec46860e2b2977ecd36257b80c109d23a83d82c43fa0fd973bc5d0b8ee4cfb828540183c392154878ce35ce5cdc99ae14757e866c4c5cab0625fc1f463a7c6adbc18de8f1410c2ae844b59f443296bb12ccf149d5cc7b85cea10f95569b0526882c1aa19fa197579efcb4dbab0d7580c1b05468c24dc0e1ded552a2ba84db32c610029a5426a9700628ce167f9aaa9ef151ac05cfdd6a66ddbc77d27dde1599098cd677bc7c92fd4f8a3e3e9cbc88102818100e8b2aa080efc1684d7b4de3c02a7e9bf1703c0b361039c4b47470ec1fa5e1be63aae59dc1a6f0661b5485f99ea2d36491c17c250779cea0fb61533c3a5936fce4dd2f32c5d4ea70c9bcaa5304cd76571ad257b80bb8cc2b073ae9964152f9bdd78a7c58b38c893d4a1971b9ac64aa99b8db043d6224db86e8f76183fbc46de2902818100d3eba93f76e2457e4324ae71f1d5adad220ef8b8fe0a37c71a4b40b2e02d3820b091ce43f50239ab49b344cb9c31894286ce6379373553b5ff9a78325f02f1fd47efeee66aece1a48102b268599e89e4d917506718e64b99eaf47bb3ea72406172257139d279383508b6ded3e7ad9a07d275dbe20a174486866c0038e97136e9028181009aafda540d120b2e37eea6252266d8fe0ca094032aa4a9cb69109580e19c99d34c83067d489d3192d65dcc1f970a8321caa908a5513e60621d5aaed48a471e75f84a19190ed5f03a737e1c9da51732fa846d7c52315afb392d4d8dee781ef3f01ffaf758fb606ad558ae08cdb4af815c44ae3e0a2537a138ede9456969117b3102818100a99397f91ace714159c50e7a4b43eb17f17afd783a803ea5e9da71c9312dbe0e1a7c720b5b110ec88bcf11abc42eb7612eb2145338e4493a0770b9e1c4b97c9e6a640a4d031ece686e7b93fb804b2698a346cea5d0fce75e20eec5d5f032c065b98b50912e64a59f7a7baacef242ae50b80e6b86f3002f6b5e4129e46098a19102818029055908c97eb39712df34b9078c6c94b6fa3908c2809c7da36f9ff282e79196180a1da03fa67fda6a000cb6e6cf75707921c2243d8a92cccc150e874b5691c5069bbd9d096b4fc05fa2f5f7ae0af2699057b42c0f2b83236de4542781ea77befbb6985cdc5a878518eef254942330898439723840294369519d7103757465ca"),
			},
			3: {
				SK:            ecdsaSKFromHex("182fc09c07dc35580f1e2c67cb623a71aa2745f79824119a1095c0d373bc1c42"),
				ETHAddress:    ethAddressFromHex("ac8dea7a377f42f31a72cbbf0029048bda105c37"),
				EncryptionKey: rsaSKFromHex("308204a40201000282010100d9d5a9e7aa4d9fc75ed0a5a77540b6026b9ea6913a635edf1f5481f81fd0eabbcc3fea37ed11edd38086983260135d25ed4d2cdbae6892fde3787074e892727602639577c0729e6446bb289ec87f6bc8071a6ad9120cfdc892910f005a56fc466b9f9ebb9adf80e14f13de129b82eeec95d0c9ebba4f3952786d8287ff3146a4e00af5c44aaf1f7611a5791dcf05dfe076733d89bca404722ab9810695bdbc95839f47938367ae5f829b053988cb7d94f72825ede566bcc5aac15b227a1d6899efc428c7829ccb38839196b39aa091e714f8fbad4ed75694ada2f90b70a15b147114d360ccd93767c45db0d6fc3dbc58d024fd1fd2d0fd1301823e7e6432cd4d02030100010282010100a62e9f80f1e668278408eee772c71c537a60bd37fbf0453738c292a885352f6e77a2a6ff65679125125f1c0b0a4a9b7c4caddcb3f7392632746fb4732bde555dfbf296db95c09b5f6aaa6b91bee99e832a10184563c4ef732d85668961620cf178377cb428b1abb3b74d33d4c438be27551fc47b8655dc2833616ffc6a4de0528d7987bf8621f3586016bb47f8e81cf04657f471ce6f0d9d71dd7da3e7ef850af1d20551c0cdbbf77fe6e39dd58434083dd20e7f4eddb4883e67db7f172d26b35bb559aa3c7a9c3a0a46e665857463904973d31443097ce1ec37ba8f15efa9c36201acbda208350dedf94b9c52699a8188267a87bcf48c73dc2149dd2c9f53ad02818100f2d7cf3ae35d2e09b5aad153b8b3819c7b8196491ff936abebc7bd86a967e08af4e21e11865833c50ca6a286eca8e9554dc93b6a2acfdb5f38258f41075a7f8fb0c1240e37d4371bab40d8a6eed71974e7c5f40455018f7b50700c028d7c9d2a26b3e6f234c588081d6821a8bb8518693be4c9eb222dbfb80d3cce0369c03e0f02818100e5a2fe04fb9a0cc637ed2e97df12bd2c6f859dadbb41b2f251ab705419c4049779686b9b6275e57fb2950af2816ac8697ec9ec7a98f5899cdf2b377aa3aa0807d7b609afff7ecbe3d539193593f3d209a539509fbe501251c4d35367ed89fe0aac2bca9b0e0a12e427c506aa3dae1fa98a495f43d4086a33b43c659e2aeddae30281802a5b580af6735f3f544f8a196742f01d8231552c46066af1cbbb58246fd1ed896f332d79730c59634a549a4e9c62cde8121c425fbf3de80e90b5846a1c453db0ab6cd4c4221ac2cdf1adeadc1b16ab9b077e3094bcdafbd2cf71ebb65a455d08681dc2ef8622da1a483ecc7828d50b2ff7c16d32b51073bb3f9bd67723efe3230281805bb0d12cbc29aea01704a56e0eac34cce15ac0b2f5ea2dc183caa8776c3250830aff1eb854802ebae65b8c9b780163347c63b400dfc26ac83073d91b26ee65767c333b7b02d16627faa369e572c6103fb9b140f807cd8103154c2c297b3776305cbebf8f59f3bbc74df9e5c764097aaaff847c7d60d45b5379cc03e73bcced7102818100e82890aff55c0ac12bb1be372cf491be5b20d54438f1ff96b32d00b59c539106478ce6d7b6a1200037a4998c12dc7f6f2479a8ca7c0ab0e8bc019d82047cdb315ed2f20cec4ca1f118ea778ea2bbc3c78f20258fd025115c9451e90120c46f0c95f5aeaefb6cf37428d62811051466d5f1d3301144dc7c9e735c0bcd114625a1"),
			},
			4: {
				SK:            ecdsaSKFromHex("4d3eb49ca01aa6b715a482633fac171f26e957874dd64fe14d8645ddd11346fb"),
				ETHAddress:    ethAddressFromHex("aaaa953af60e4423ad0dadacacab635b095ba255"),
				EncryptionKey: rsaSKFromHex("308204a40201000282010100ad489826fd514cc2845646d59bd0846fdc9b77c58fd3b79dbf07f1a4d0d98f5210f5af483c3a02769927961c9de52acdcc78d7a87e720b574d40f93b5a49095e26e95fd5ccfc3976051c8cb18ff26ac8bd1a95a759b9cc6fa3b75aa77687ce103874680aa922b5f0b65831f9903404da1ce87e15276ab956cf6f72622274edf8a34b743575e870e67368d6e0da4167da9e7027dee219c65c7fd66f8484d249fbaf59534ee553d756dd07f9a50c26334fcfd94391f2b5583b67a8a4c2239b5de55f1b21a8d748312010ac99baebe617183fcb0fcb28b93810344089f3cf2e57969d3c6f72b340ff3c2941fd7b921f314440aec96bba353d848685b305ea2732670203010001028201004dc6627c4580830a5f6975fb9426dffa7132da6c32e4dcea117ed8479871bdb120e994d5c02a6d469bf1379ffa828c56b86a98a908afd94542e861b4f10e0d055443b4fefa354ef918cc3a9dcbb50b96b3c1c5dfca16e99a460a1ac7451d29310095c6c8da2739302437ab9e8ec9ba4fc75fd68f5a14bdc127f3a68c4358e621d0c62b855809c0a97cfd617ce639864be5b5d367eb4ebe37e647856ffe2d7dbc43eb20c8ce2fca5651dcbf682a85848297375d611dcee007d4d1edeaa7eb47431b1ee2b24d929f4587b55368c37adc21adeb72d4bcd4046c00954007177a28a4df766be75bb64a60d43ec02f9306e405485767fd5e010e0670f04c215a662f4102818100d995225d2236d885ae9818e03e947f88ac408f4580bd7166bc17e2e02d58c7b81bcd74e5ded04ae6f1d65b87232b1d7c3a7e3a7b8c8c5202731549d1f9ea39c769364003970d703634f2e0d50a46dccf8f7972756b1bc01fb183bc3915dc9875ccb488a79e09af675fa456a1dfe4489bcc49ac13c3517146e03ff6132d2f1e8702818100cbe11e635ede1aee24e1771d187da30161c521795f7e11a99997828f3257df51ab6a56ab62eae6bf691bddcc39547dc88ce34faeb1254f3c1fe48a1cbb89c21bd56a154533a77da103962fcc5485d82291a828e9a6e04e42ad135bd8dbaf7a30ec4845392517ed89ba23037070943a4cbd257bda17a4f8654f40c26400ef65210281807d5ea3184ad8935623cddbb78a17828cbbc3cf49daee4d6346c9f49dfb4306811cf3fb81602b609d45879fe173f029e324c90ae5998c58ccb486f5ac19764ea88a050a498745e4fc36f2237e5d978b2fc599d2cbb9559a1428f2a107bb830a0e064f97d60d07c39baace4464ad5f1a3f3b2cd00beb25084230806a478e67720d0281810096849ceac01f39c29777dd789d9c23bbe172a843f33c1fce1696c4ccf35dec815f0c22f0651707444955496a7ce8e3f42c0fa5c45304387b2b108ee6a78e0cc07fced1e5453d62827d23642676405a512b37fafc8537149025372597f498989d85d3d5475b1b4f435f287a6188bbe64ec155eb1a185ab308187ab7091da7a00102818100c157cce973ed91393e04048d321042feaed05d9cf4ec21e1cb0ed584ebad80c06810357fc45e9324173c4bbd234288403f15ad58e83184c2dade6e47d897ce100fc6c3bd4e6d1ef4b5af1f6621dd111b27a6f14f8850e89b61c3970234696d1a487322e972cd835d8ff35a0571585c827b3c630f4474e814dfd88dc4bc113477"),
			},
			5: {
				SK:            ecdsaSKFromHex("201381712fd8f14dd974ae6e0def0956518eca5a279ec3940b0f9f4a406dc68c"),
				ETHAddress:    ethAddressFromHex("72d3c5cbd1c7e8edd7a332d6cc66e241fc048f4a"),
				EncryptionKey: rsaSKFromHex("308204a20201000282010100b37f19eee6fee3633598980a91ea1cfbbd2d3863ca6aef6f729ad3ed808364724a4f975b0008f6aa3ad56d8a19b5edf452b0f0e6b52d04a66fe4e6f8ff721a4f2cef6db31bd126d98fa4aa87321443c049d44c191ab5b20ab9c443e42f0b761ecaf1332abb8bc353598ca8e43d7728191efd3775ebc2068f27a345ed4a7e4c701ee60d2298ed6247fb9618c6fe9907ed572fd9bbaabf859dce94430fb054dee4a04dbbacfdd659dabeef5d535d631d50970bda17b085d186107dd697fae36e8df830f19c016d989407e09fbfd8aa11f642a1b6db22c290bf228b8982f96fbaf24510667aae17d3681f0d729eedb152d5ef3c6916f882d3e21b17c9a39c2c503f0203010001028201006d7829b7c2d756946dde777392d3e6033db7b37960bce0f3e64038d9d313cf11c8f24b8bab34cc42bb88e8ba5dbdcfb6bf2bbc6fe7b4e1ee23b5c58bbc36b986ea0fc7a68163883f0d54cecf8f223ec3aa0338b9e2c947213574563776dd9597680bbc39e691717986d6bb361faa692110fe3b71c66bd9963b055fa33d585382d335d02271892d922c1b0d3e5bed2bb69385a9d2e242704bf91640e1df37fa7c4f9bdf4bf0e33448032b55e6616500965d42ae72b9697d9e674533ec5fa8d6f86439682a7e3344bce235315ade3d8b59f478b91f9c5771cd57993ffac241060d54c6c79a95e09e26f37922cbc6381d6dc530cc90ecca2069c9f6e4906467ae8102818100c3a757eacbe74bddbd992ce43b78e2be3bae3c63971531138774dffb8849ed432c7d5b7c7e28b4ea44768d4340f2ed5d60ad790d789e49fc9c65ccd0c52bfb456288801ab0b011994aca888898913a984deb95e1a01212a8325cc649a8b1c76c89d4da515db02f4797c9e809a6098d57dccf91ad8d6d96da0e69b949c36cf0c102818100eadbffafd4fe75645861a322b551c93921348756e91bd43bb7ee895c434a59375f6ea49bc494fbee219d170b686fe48e0c04cd1528b0f57ddad500aaa71bd4cf78ce0ea6cd21f6c205e41a4d78c740454de8b61e56089e15717b76f905581a9db329616e78c7cad0d8bc02b573b2543f3de112ea6977f4f1b19c1b7cc44880ff0281805ff3557e64790e0fb4c7c5e837f254e08e4c28797ec279cae6073f410fd9916dfc078e32437c9b1cb86e9b607c1da6a2c0a2d256f4ec4bc482beb9ef3883153b35d3535fc37ed562a3f7277635bc234c460a5efac391996cbb261c684b3ec45a4a4e04b31a8b28e4a75ff157aa01cd3b65a2b602b2f527a1d0a7b0a2a82069010281801a928fa85e49f810456baea083b1603a0586c2f55364a1abac10e21bbd455138d1a45c1d7fad779fa6cff64685277bcd92908c7fa35dfa38a624c971857cc1a443bfd4aa8cb5160d37cb6a2a6fcae37bb3e7eb8b1d22d67808a1f6811058ba92332e3066e6657c8e0aa7a30ad2af4f96e4326e0875ac6bdb58c417dc12fd3d130281806b7ca82b99544a1bac499c0abc7a48acc8ff14518b39c1bf89c6d36077f1d9f7661f73e19bc4bab2609017bc5722e441729a94a90d83aa3c650715fe6a329e7180efec8b0aafb3b2895a7f6e682cd70dc7663e23ec04cd139835a7758a3b236ff7aa43f713c278e47bc09763436c8749a622891b33eb5d3eb6a15b3710ec2438"),
			},
			6: {
				SK:            ecdsaSKFromHex("02a17f657d3d96eeab9a617bc6b383873fe38a4d150971b967634ee4feac4c8d"),
				ETHAddress:    ethAddressFromHex("34e59dd81b0f832122df98c8cbe8fe4f4f3c31b6"),
				EncryptionKey: rsaSKFromHex("308204a40201000282010100a55bdd8dc443637e6ae1ebc0b25fb0ed2e6865739d414d07848aa9c98f125b547ba5a55154388ffbb032b5952a12f8582dbe66ab7642dba753a62e134a9f9c3242d9d90b4df5b8cdbebd6b045ce643e3a3c07c355dee4eca5960a6dab22f3f66eb2c6ae202c7031837dad87d262d9baeb7b6cee6abaeec3167e8b304fe72a6a76e6ea523ea6bf65ffae841e1ecb5906f9a1da75fd20c0ee8ee2e9dc04408f0363b44ef4e6416eb76388cc11170f15ced581fcb4815dadec64af88453d1f40e7e74967751f8cae049640be1913cf67f8dfa96e48907bff212877d09a555bde3a6f631d447e9604e54448c834f0a4d91a8c5aead1cfa232c8a5b34b3120cb2e6f502030100010282010001e3268833b14135742ad7f1ff173081c481d4869948e184307314b504390569d56f728f97127e3235349ef5f0e0fe8ca319053af7c293973951303d70209a3bc89f8be6a12128d6d05281222f9d41311bf15a799174e2d95463d203b4fced1053a6d2217a3ea33e6784cbebc1bfcb8316fdb326d6d6cc43541847d2cac4ac3a40497ec720d23a90f6edffc7e65fb2ef498eefe3aa6617e04b0cbada9b79ab5e9e4c4cfeb75415e94d36f20f7d9cb6355385fc696ffdcfb931fbe5feca037162ee40e5e30668141658682125e6a10bcf711ee8ea0fd749519f6ef86e3dd81c34ebe3587aa2b0f0906508cecda9bd1122ad7acae5fff3e97f4ba9e8129239900102818100d448c47ddf24040660f82fb40079a54b4fa0a9fa0a6c27fb5046bcf2105e5323e5d894ed84760e9713fec12d0ebcdcfd23c9e95f4cc613d57506a851991c95386c4ee22a65be9bf93902f053bfc6f2627239074341ed6f20f153ae918c184f8451f5420cecc55de28be5a613ecd4435dec5374fc76dd9715a181965ee4a933f502818100c769471be9f6046c414ef8e3429e099b394c9476cb212d4c71bf86adeb03fe2bc60cc4206bacc262dd486df22f7bbf954242bd24e1fae12f39819c1d9946911a591bba24bc6c9c77b316199d64e78786ef9ac5aad1ae855ed909ea67e2da446195161d3051a0ab89d0e1c93831130474647d507f5da7a7861ff648580466070102818100a253aa7d1dde6a7d7e350a35388fcc87d431e5086063e806d291e4f5acf293dcc56b622665bde8d639e1fa51bc0d4b66feb0ed15849d8a99154dabf40982c3d04b71de9bd1057a3b8f0ee23b0850d713d4882b3790f8409c0e2d913596cd1830f482f8a8ed7cd697dfa611e2f69c318f66a142b9b3232adecd8b4c32efe33ae902818033e977469008a8ac19f05a20a78606d02f017da0d34ea6c140d77053345c4cbdce882242a2654e1178b3d3537a030823ee24fba26f65e55b6ae80fe130b6cb2d85c70f15632c0f2ba62679b29cc31d6806564f6121c7021767ff09d3d39da8b192a338240d0bfbbc1bf1bb75726915fecaee48976fa5269a6715b14da08f8301028181009ba547ab2ad11147b1199e32233f6c3f082a96e954772ae11cb0d6a1ff0f4a3c32b1e72d7ba960c2d22959e5b6730fc17d2982747713eb539df68238d010f3c306ecdeaf5fc67da9857adc0794318cbe26678f92bb74c924d4279c7cac5b0d41436846c719407be222ee1c21e021b89e1b8827c2669494464c2c920ade398366"),
			},
			7: {
				SK:            ecdsaSKFromHex("d370c6a295402dfcd3f4d166170b88442db9684268ee4d6e2b9307a1b1df1beb"),
				ETHAddress:    ethAddressFromHex("389d05783094371063d9bf55e46fb67f86c2ee07"),
				EncryptionKey: rsaSKFromHex("308204a30201000282010100cabf1fbe3c15b2ae3b1be1969b79e42099536a361045acbeda677a9e8785a5875663901c6aec1af7e1b26224c9daef72cdba9261dd71285cbb51dfbc7ba415250a58af23248eab20bff2f113a1f432d2d294664ea6be14b449e627707a3284d7840ce4eb394afe79b2cfad16fe3c9dab4b4714be3464f87f1d629cae8d563aae24650bde0a4c13727629e9f48dd856130521b180d16c668fcc2d4ee7bcae5ee69283d35b89587dc78dd9d84ec92c16aca2dd027e06bf1f23bc8a86d407b4eeffd93653af92febd4c4c871d97671cf962a7d07148bc7b475fba6174458c83ab8a4ebe13c7943cfafd36d8a57dfe24485f6404d6f49b133d0231bcb85a0fb68271020301000102820100250e2d750d7241c80a519c37748f209cbca93c3e495712ad87296685d6eb1c47d2083c6c953635ef9c36882d851f18a878e5629fb4635c2726ad5e210ad0007556a0c2d1bf7abbd82e7cee86d210d9c1226fb10b2afa8eba2ccf7de1d6d3a8e7e2e0a06e4578696e40ba283e8d94f2943e1bedb49dcade880d0cdaea2436e05e63e1208fdfc3fb15aa860c0b1d28773069c0a6632889dc7ce29b9b0f24e072cfef47cba908340bba1cba41f3b448f5c3a58b9d65d5fe71670fae27ade554010b88db8c335fb70cf96b29acff4f5bd58babfa8497a19ab96d7b2f92aef31d69b8dddc33cc10013dec7142933c40e0cddb41b5bcf9d6140ec59f83e95c22ab640102818100ce006dc955ca377bc9ef6016772699125cd5f14d74efa8d8f9cbcbdc8e46fba16a6dc04eeac83ae5d0cbfad326c1da6baff21b94305218ed58cb451f6bffeea56824b815f979562d0083a49990977281dca2308e75496a65904a22b1f34b6c8ec73784a84b3d6f436817bf7818d7533f6e22b4515eecd23e7ab35a590978ac2102818100fbf471f254c2f1164ffdb3433d8efaaa34f27413693418673506a4a01046fe6238a262e11b9cc97b8680eb96f1859754956840c6752cca97ff0388bf250c8904de425b76770f3da648664bb4185e02d968b12b2e53a04065d3779550f69c1f8f181bf5d53655611da27d9b753e7ca530b9ce28a18b9d877ef98ecc69d5a68c51028180517a27f22705693683e332cd0fe96b47b10249838a49b42dc5770eb5b86c68e02a1928a3ce06ce0cd1adac1251d5008ff132402837887125872636bbbbdaa94830cdbd25abdb8af317adf9af675a0f473fbdc298c5d8f8c51cf1c5913e9a49609b78e0f63374240ab424186de6dd5ba6cde7da0c09108003884261ecaf6b54210281804dae6a4b5ad2d7de173f933b92093943ad1b6baa686f456edcac75a95c1b6767052b1bed67c40962ea6f69339ab7a396d291d816d81dbd40ebc13d3221cc219abca41ceb037e5175a930d0fa6fe0dc6407a1483cfa4f984b4ccdbbddc08b1637da2914bc6e0a18ed38221e022207f02e7bbb124fec69df52c8c2bc478d35d26102818100b80d709ef76d0c32c9ecd6df6d08bb00d4f5dfde5593c8bbeb11873819d191ec2e1cef35e403f5e803a325c62fbc2440b583f05c29d3820471659e5cd1ac2c7d12b1e07ccc116f9e59c7a1ea5e40149b4011603f0fbdcf8543efb3514957d300188e2074eeb297eac178339fd06a37ad81d6908d50218cc1c7fe40428edb7a4b"),
			},
			8: {
				SK:            ecdsaSKFromHex("f930a907fe0cc4eff82a85498dbc1e6405f42e9410092196dc76b6c8912c7bc1"),
				ETHAddress:    ethAddressFromHex("4f1bee79773989347e553cfbb853736d027fb84f"),
				EncryptionKey: rsaSKFromHex("308204a30201000282010100cc06c90a7c81a8e2fc6d5fbcb25537b75c1c22b581a761f8fd60612cd03e19efe8eb75a0034e61a44711562d173302824be4f3ab42f0d87410d88c515634044a4277c0ac724b760e48e46a0409983419b01d40881e16545e2041102ea4b6c38134dd56431945c5b3489341f5027e3f74ea7f577e376e7d31a3d6fcfa21fd7606b8601df1a37ee1696d32782132b59c6ba6d7e3e987859cb1554186fcdde258267cd3a41c0ec7a085bfb891ef969c6d39b4a96c4539e77dbe4430c401a4eee1464b377d9e0d9b26989b4107be0288332ef10c8dae4c1a992cf2a220102d7f54b0d492856a19dadece78e945dd12f7733948a9ef57c1f1fca9ffd771ff41efd4f30203010001028201005247d24016623bf7fe912570f602840bc06be05b8ec43030b80e6c622441473887989dc1405415f0a870876e7bd2a88a5f8d1fefcb7951f1ccf167f54d6c80e669d3ddb22e0ddcb87a1113e838ee56e49d2fcedc9635af249ea15ea350ee1bfe3991a1be41acefc413dabf58cdfe981cd08d367dc2611ec02c3101a8e6984f4641a1af1a2d9cdd3d71039aa72fd38b0da40c09f4f16ecdcf1f32534362177ea95ec5cd019d8c02cad674aee732e302b2dfa6279b19302522bec94855296ab3a4aae26381c00581ae931d67ff8f0cf2340d72af32002a8d6d2386e57be40dd078746730705077d6f7e07efe4c425512863779ef1f567ae02f5db4fe01ad77220102818100f731ca7f8a7675ff7da2cda64d7da75012479ceb4549c23016a1fa809947b7f7dc6416708e87489bab9fd77bfa94ceafeb31e0c1f6dd8c7da8c376e63a7f987c1af21681f8003d5794b157388030c0ba6af33973b99c6a901fe086eeb6bdba4e1d2b696b650afc0e956c57173044205e6bcece1334a9a3028da7133ae859a27302818100d34b5686f45515dd4b0b6fb7a41f310d68a6891e93b6ee43d36ca288934dbb3295849ce1ee44a404b8e0fb6d1a41550fc77b27c6204607eda34fa1c708b95a3120388e2e79115a9e2385c2a4f08b2871da9796c8bac7f943ea9062391a2456319e973d8d4b5496c1993a1c7a85cc9880ff10b9ecf4b50f1bcb7d742f9423e38102818056e53be805c68ac85b63e5a2f64e9b883c44cc56b02eb382b01214bb2c26d7f6db949b86c9b3a8c4805a5a278cf8ce876cc845d8296dcc3b481e1e27e49c81ffee80f7848ca798e8b6ae7898b6076d589acc11802ad95f6476b038fea562a0a16103a7b546f9cb8d5cdd8ee7e9e1a8f7483294a28fbaaa40f586abede34bcf1d0281805e800068055914994f9a02d2305e1ef32f4de45fbf92fe476984d9c0999917534d59ed4c82e342343677b11b9fb57e94bb1412bae2ee4f5772460845db5a02c39bf48f6aab8d1e6941dbee2d14c438478b8b66cdc9f3ec40fae4ae79797eacea2e52d81d9c866d9292b451ce5e8f1dd9fbba005dc12845649a0336f69c9bdc8102818100acbc4f8dca8dfb22bbcb39d335473b3ee33464bd24838c798338c78e5594c9a4bc69b2d2e1af88c1836baf196e82e26bae14603e4d00f8e005e7619912ac4dd95b9b33e1960f9cd29994fdfe2958a2ecd3bfa359abc29452b2f933c6f6c53b4a0ba212e642b26d39fefe586763379f8a937e0694474445103146cb906d78c8d9"),
			},
		},
	}
}

func SignDKGMsg2(sk *ecdsa.PrivateKey, opID types.OperatorID, msg *dkg.Message) *dkg.SignedMessage {
	signedMessage := &dkg.SignedMessage{
		Message: msg,
		Signer:  opID,
	}

	root, err := signedMessage.GetRoot()
	if err != nil {
		panic(err)
	}

	sig, err := crypto.Sign(root, sk)
	if err != nil {
		panic(err)
	}

	signedMessage.Signature = sig
	return signedMessage
}

type TestOutcome struct {
	KeygenOutcome TestKeygenOutcome
	BlameOutcome  TestBlameOutcome
}

type TestKeygenOutcome struct {
	ValidatorPK     string
	Share           map[uint32]string
	OperatorPubKeys map[uint32]string
}

func (o TestKeygenOutcome) ToKeygenOutcomeMap(threshold uint64, operators []uint32) map[uint32]*dkg.KeyGenOutput {
	m := make(map[uint32]*dkg.KeyGenOutput)

	opPublicKeys := make(map[types.OperatorID]*bls.PublicKey)
	for _, operatorID := range operators {

		pk := &bls.PublicKey{}
		_ = pk.DeserializeHexStr(o.OperatorPubKeys[operatorID])
		opPublicKeys[types.OperatorID(operatorID)] = pk

		share := o.Share[operatorID]
		sk := &bls.SecretKey{}
		_ = sk.DeserializeHexStr(share)

		vk, _ := hex.DecodeString(o.ValidatorPK)

		m[operatorID] = &dkg.KeyGenOutput{
			Share:           sk,
			ValidatorPK:     vk,
			OperatorPubKeys: opPublicKeys,
			Threshold:       threshold,
		}
	}

	return m
}

func ResetRandSeed() {
	src := mrand.NewSource(1)
	src.Seed(12345)
	crand.Reader = mrand.New(src)
}

func GetRandRequestID() dkg.RequestID {
	requestID := dkg.RequestID{}
	for i := range requestID {
		rndInt, _ := crand.Int(crand.Reader, big.NewInt(255))
		if len(rndInt.Bytes()) == 0 {
			requestID[i] = 0
		} else {
			requestID[i] = rndInt.Bytes()[0]
		}
	}
	return requestID
}

type TestBlameOutcome struct {
	Valid        bool
	BlameMessage []byte
}
