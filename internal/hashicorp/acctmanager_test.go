package hashicorp

import (
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/consensys/quorum-account-plugin-hashicorp-vault/internal/config"
	"github.com/jpmorganchase/quorum/crypto/secp256k1"
	"github.com/stretchr/testify/require"
)

func TestImportPrivateKey_ZerosKeyAfterImport(t *testing.T) {
	byt, _ := hex.DecodeString("1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b")
	// we only need to set the private component and verify that it gets zeroed, regardless of if importRawKey succeeds or not
	privKey := &ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(byt),
	}
	a := accountManager{}

	require.NotEmpty(t, privKey.D.Bytes())
	_, _ = a.ImportPrivateKey(privKey, config.NewAccount{})
	require.Empty(t, privKey.D.Bytes())
}

func TestSign(t *testing.T) {
	toSign := []byte{144, 88, 241, 72, 58, 165, 101, 84, 27, 223, 99, 42, 219, 200, 216, 141, 88, 19, 158, 86, 121, 6, 130, 26, 23, 68, 47, 90, 6, 69, 156, 112}
	wantSig, _ := hex.DecodeString("ead3d9a19ac3fb4003c50f2d85e27072dac4e78b77903d6061d8619ba671db0551ab3e72790a7d0c722a3c6ee070a75fa08bb04b7d3ae2ca0be1963bbbdf94c401")

	byt, _ := hex.DecodeString("1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b")
	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: secp256k1.S256(),
		},
		D: new(big.Int).SetBytes(byt),
	}

	got, err := sign(toSign, privKey)

	require.NoError(t, err)
	require.Equal(t, wantSig, got)
}
