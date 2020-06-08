package types

import (
	"encoding/hex"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"strings"
)

// NewKeyFromHexString creates a new PrivateKey from the provided hex string-representation.
// The hex key can be with/without the '0x' prefix.
// This function expects Quorum to have checked that the hex is a valid private key and so only performs a valid-hex check.
// Be careful if using direct user input as valid hex may not result in a valid ethereum private key.
func NewKeyFromHexString(key string) (*secp256k1.PrivateKey, error) {
	key = strings.TrimPrefix(key, "0x")
	byt, err := hex.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("invalid hex private key: %v", err)
	}
	prv := secp256k1.PrivKeyFromBytes(byt)
	return prv, nil
}
