package account

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewAddress(t *testing.T) {
	byt := make([]byte, 20)
	rand.Read(byt)
	got, err := NewAddress(byt)
	require.NoError(t, err)
	require.Len(t, got, 20)
	require.Equal(t, byt, got[:])
}

func TestNewAddress_InvalidLength(t *testing.T) {
	byt := []byte{1, 2, 3}
	_, err := NewAddress(byt)
	require.EqualError(t, err, "account address must have length 20 bytes")
}

func TestNewAddressFromHex(t *testing.T) {
	var (
		want = Address([20]byte{218, 113, 240, 116, 70, 237, 30, 202, 48, 68, 133, 221, 0, 196, 130, 126, 208, 152, 73, 152})
		got  Address
		err  error
	)

	got, err = NewAddressFromHexString("0xda71f07446ed1eca304485dd00c4827ed0984998")
	require.NoError(t, err)
	require.Equal(t, want, got)

	got, err = NewAddressFromHexString("da71f07446ed1eca304485dd00c4827ed0984998")
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Len(t, got, 20)
}

func TestNewAddressFromHex_InvalidHex(t *testing.T) {
	_, err := NewAddressFromHexString("contains-invalid-hex-characters")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid hex address")
}

func TestNewAddressFromHex_InvalidLength(t *testing.T) {
	var err error

	_, err = NewAddressFromHexString("0xda71f0")
	require.EqualError(t, err, "account address must have length 20 bytes")

	_, err = NewAddressFromHexString("0xda71f07446ed1eca304485dd00c4827ed0984998da71f07446ed1eca304485dd00c4827ed0984998")
	require.EqualError(t, err, "account address must have length 20 bytes")
}

func TestAddress_ToHexString(t *testing.T) {
	var addr = Address([20]byte{218, 113, 240, 116, 70, 237, 30, 202, 48, 68, 133, 221, 0, 196, 130, 126, 208, 152, 73, 152})
	want := "da71f07446ed1eca304485dd00c4827ed0984998"
	got := addr.ToHexString()
	require.Equal(t, want, got)
}
