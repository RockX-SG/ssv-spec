package frost

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	mrand "math/rand"
	"testing"
)

func TestMockCryptoRand(t *testing.T) {
	src := mrand.NewSource(1)
	src.Seed(12345)
	crand.Reader = mrand.New(src)
	n, _ := crand.Int(crand.Reader, big.NewInt(100))
	fmt.Printf("%v\n", n) // always 26
	n, _ = crand.Int(crand.Reader, big.NewInt(100))
	fmt.Printf("%v\n", n) // always 86
}
