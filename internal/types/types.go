package types

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

type Account struct {
	Address Address
	URL     *url.URL
}

const addressLength = 20

type Address [addressLength]byte

func NewAddress(byt []byte) (Address, error) {
	if len(byt) != addressLength {
		return Address{}, fmt.Errorf("account address must have length %v bytes", addressLength)
	}
	var addr Address
	copy(addr[:], byt)

	return addr, nil
}

// NewAddressFromHex creates a new Address from the provided hex string-representation.  The hexAddr can be with/without the '0x' prefix.
func NewAddressFromHex(addr string) (Address, error) {
	addr = strings.TrimPrefix(addr, "0x")
	byt, err := hex.DecodeString(addr)
	if err != nil {
		return Address{}, fmt.Errorf("invalid hex address: %v", err)
	}
	return NewAddress(byt)
}
