module github.com/bloxapp/ssv-spec

go 1.19

replace github.com/coinbase/kryptology => github.com/RockX-SG/kryptology v1.8.1

replace github.com/consensys/gnark-crypto => github.com/consensys/gnark-crypto v0.5.3

require (
	github.com/attestantio/go-eth2-client v0.19.5 // if version is changed, types/generate.go needs adjustment
	github.com/coinbase/kryptology v1.8.1
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0
	github.com/ethereum/go-ethereum v1.13.5
	github.com/ferranbt/fastssz v0.1.3
	github.com/goccy/go-yaml v1.11.2
	github.com/herumi/bls-eth-go-binary v1.32.1
	github.com/libp2p/go-libp2p v0.32.1
	github.com/libp2p/go-libp2p-pubsub v0.10.0
	github.com/pkg/errors v0.9.1
	github.com/prysmaticlabs/go-bitfield v0.0.0-20210809151128-385d8c5e3fb7
	github.com/stretchr/testify v1.8.4
)

require (
	github.com/ecies/go/v2 v2.0.7
	github.com/google/go-cmp v0.6.0
)

require (
	filippo.io/edwards25519 v1.0.0 // indirect
	github.com/btcsuite/btcd v0.21.0-beta.0.20201114000516-e9c7a5ac6401 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.2 // indirect
	github.com/bwesterb/go-ristretto v1.2.3 // indirect
	github.com/consensys/gnark-crypto v0.12.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fatih/color v1.16.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/holiman/uint256 v1.2.4 // indirect
	github.com/ipfs/go-cid v0.4.1 // indirect
	github.com/ipfs/go-log/v2 v2.5.1 // indirect
	github.com/klauspost/cpuid/v2 v2.2.6 // indirect
	github.com/libp2p/go-buffer-pool v0.1.0 // indirect
	github.com/libp2p/go-msgio v0.3.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-base32 v0.1.0 // indirect
	github.com/multiformats/go-base36 v0.2.0 // indirect
	github.com/multiformats/go-multiaddr v0.12.0 // indirect
	github.com/multiformats/go-multibase v0.2.0 // indirect
	github.com/multiformats/go-multicodec v0.9.0 // indirect
	github.com/multiformats/go-multihash v0.2.3 // indirect
	github.com/multiformats/go-multistream v0.5.0 // indirect
	github.com/multiformats/go-varint v0.0.7 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.26.0 // indirect
	golang.org/x/crypto v0.16.0 // indirect
	golang.org/x/exp v0.0.0-20231110203233-9a3e6036ecaa // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/xerrors v0.0.0-20231012003039-104605ab7028 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	lukechampine.com/blake3 v1.2.1 // indirect
)
