package account

import (
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"testing"

	secp256k1 "github.com/consensys/goquorum-crypto-secp256k1"
	"github.com/stretchr/testify/require"
)

func TestNewKeyFromHexString(t *testing.T) {
	var (
		hexKey  = "1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b"
		want, _ = hex.DecodeString(hexKey)
		got     *ecdsa.PrivateKey
		err     error
	)

	got, err = NewKeyFromHexString("1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b")
	require.NoError(t, err)
	require.Equal(t, want, got.D.Bytes())

	got, err = NewKeyFromHexString("0x1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b")
	require.NoError(t, err)
	require.Equal(t, want, got.D.Bytes())
}

func TestNewKeyFromHexString_InvalidHex(t *testing.T) {
	_, err := NewKeyFromHexString("this-is-not-hex")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid hex private key")
}

func TestNewKeyFromHexString_TooShort(t *testing.T) {
	_, err := NewKeyFromHexString("1fe8")
	require.EqualError(t, err, "private key must have length 32 bytes")
}

func TestPrivateKeyToAddress(t *testing.T) {
	byt, _ := hex.DecodeString("1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b")
	key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: secp256k1.S256(),
		},
		D: new(big.Int).SetBytes(byt),
	}
	key.X, key.Y = key.Curve.ScalarBaseMult(byt)

	addrByt, _ := hex.DecodeString("6038dc01869425004ca0b8370f6c81cf464213b3")
	var want Address
	copy(want[:], addrByt)

	got, err := PrivateKeyToAddress(key)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestPrivateKeyToAddress_InvalidKey(t *testing.T) {
	var (
		key    *ecdsa.PrivateKey
		gotErr error
		want   = "invalid key: unable to derive address"
	)

	key = nil
	_, gotErr = PrivateKeyToAddress(key)
	require.EqualError(t, gotErr, want)

	key = new(ecdsa.PrivateKey)
	key.PublicKey.X = big.NewInt(1)
	_, gotErr = PrivateKeyToAddress(key)
	require.EqualError(t, gotErr, want)

	key = new(ecdsa.PrivateKey)
	key.PublicKey.Y = big.NewInt(1)
	_, gotErr = PrivateKeyToAddress(key)
	require.EqualError(t, gotErr, want)
}

func TestPrivateKeyToBytes(t *testing.T) {
	byt, _ := hex.DecodeString("1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b")
	key := &ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(byt),
	}
	want := []byte{31, 232, 241, 173, 64, 83, 50, 109, 178, 5, 41, 37, 122, 201, 64, 31, 46, 108, 118, 158, 241, 215, 54, 184, 194, 245, 171, 165, 247, 135, 199, 43}

	got, err := PrivateKeyToBytes(key)

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestPrivateKeyToBytes_Pads(t *testing.T) {
	byt, _ := hex.DecodeString("1fe8")
	key := &ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(byt),
	}
	want := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 31, 232}

	got, err := PrivateKeyToBytes(key)

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestPrivateKeyToBytes_TooLongError(t *testing.T) {
	byt := make([]byte, 33)
	for i, _ := range byt {
		byt[i] = 1
	}
	key := &ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(byt),
	}

	_, err := PrivateKeyToBytes(key)

	require.EqualError(t, err, "key cannot be longer than 32 bytes")
}

func TestPrivateKeyToBytes_NilKeyError(t *testing.T) {
	_, err := PrivateKeyToBytes(nil)

	require.EqualError(t, err, "nil key")
}

func TestPrivateKeyToHexString(t *testing.T) {
	byt, _ := hex.DecodeString("1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b")
	key := &ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(byt),
	}
	want := "1fe8f1ad4053326db20529257ac9401f2e6c769ef1d736b8c2f5aba5f787c72b"

	got, err := PrivateKeyToHexString(key)

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestPrivateKeyToHexString_Pads(t *testing.T) {
	byt, _ := hex.DecodeString("1fe8")
	key := &ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(byt),
	}
	want := "0000000000000000000000000000000000000000000000000000000000001fe8"

	got, err := PrivateKeyToHexString(key)

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestPrivateKeyToHexString_TooLongError(t *testing.T) {
	byt := make([]byte, 33)
	for i, _ := range byt {
		byt[i] = 1
	}
	key := &ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(byt),
	}

	_, err := PrivateKeyToHexString(key)

	require.EqualError(t, err, "key cannot be longer than 32 bytes")
}

func TestPrivateKeyToHexString_NilKeyError(t *testing.T) {
	_, err := PrivateKeyToHexString(nil)

	require.EqualError(t, err, "nil key")
}
