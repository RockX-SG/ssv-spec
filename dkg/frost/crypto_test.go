package frost

import (
	crand "crypto/rand"
	"github.com/stretchr/testify/require"
	"math/big"
	mrand "math/rand"
	"testing"
)

func TestMockCryptoRand(t *testing.T) {
	src := mrand.NewSource(1)
	src.Seed(12345)
	crand.Reader = mrand.New(src)
	n, _ := crand.Int(crand.Reader, big.NewInt(100))
	require.Equal(t, 26, n)
	n, _ = crand.Int(crand.Reader, big.NewInt(100))
	require.Equal(t, 86, n)
}
