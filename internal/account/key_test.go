package account

import (
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/stretchr/testify/require"
)

func TestNewKeyFromHexString(t *testing.T) {
	var (
		hexKey  = "1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b"
		want, _ = hex.DecodeString(hexKey)
		got     *secp256k1.PrivateKey
		err     error
	)

	got, err = NewKeyFromHexString("1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b")
	require.NoError(t, err)
	require.Equal(t, want, got.Serialize())

	got, err = NewKeyFromHexString("0x1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b")
	require.NoError(t, err)
	require.Equal(t, want, got.Serialize())
}

func TestNewKeyFromHexString_InvalidHex(t *testing.T) {
	_, err := NewKeyFromHexString("this-is-not-hex")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid hex private key")
}

func TestPrivateKeyToAddress(t *testing.T) {
	byt, _ := hex.DecodeString("1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b")
	key := secp256k1.PrivKeyFromBytes(byt)

	addrByt, _ := hex.DecodeString("6038dc01869425004ca0b8370f6c81cf464213b3")
	var want Address
	copy(want[:], addrByt)

	got, err := PrivateKeyToAddress(key)
	require.NoError(t, err)
	require.Equal(t, want, got)
}
