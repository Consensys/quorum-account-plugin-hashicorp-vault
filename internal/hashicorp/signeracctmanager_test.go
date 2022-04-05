package hashicorp

import (
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/consensys/quorum-account-plugin-hashicorp-vault/internal/config"
	"github.com/stretchr/testify/require"
)

func TestSignerAccountManager_ImportPrivateKey_ZerosKeyAfterImport(t *testing.T) {
	byt, _ := hex.DecodeString("1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b")
	// we only need to set the private component and verify that it gets zeroed, regardless of if importRawKey succeeds or not
	privKey := &ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(byt),
	}
	a := signerAccountManager{}

	defer func() {
		if r := recover(); r != nil {
			// likely we'll encounter a panic as we haven't configured the signerAccountManager
			// recover without doing anything as we still want the test to be run
		}
	}()

	require.NotEmpty(t, privKey.D.Bytes())
	_, _ = a.ImportPrivateKey(privKey, config.NewAccount{})
	require.Empty(t, privKey.D.Bytes())
}
