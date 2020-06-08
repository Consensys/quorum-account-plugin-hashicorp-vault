package hashicorp

import (
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	input, _ := hex.DecodeString("aaaaaa")
	toSign := accounts.TextHash(input)
	key := "1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b"
	wantSig, _ := hex.DecodeString("ead3d9a19ac3fb4003c50f2d85e27072dac4e78b77903d6061d8619ba671db0551ab3e72790a7d0c722a3c6ee070a75fa08bb04b7d3ae2ca0be1963bbbdf94c401")

	byt, _ := hex.DecodeString(key)
	privKey := secp256k1.PrivKeyFromBytes(byt)

	got := sign(toSign, privKey)

	require.Equal(t, wantSig, got)
}
