package config

import (
	"encoding/hex"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAccountConfig_ValidateForAccountRetrieval_MinimumValidConfig(t *testing.T) {
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)

	c := AccountConfig{
		Address: hex.EncodeToString(addr[:]),
		VaultSecret: VaultSecretConfig{
			PathParams: PathParams{
				SecretEnginePath: "engine",
				SecretPath:       "path",
				SecretVersion:    1,
			},
		},
		Id:      "id",
		Version: 1,
	}
	err := c.ValidateForAccountRetrieval()
	require.NoError(t, err)
}

func TestAccountConfig_ValidateForAccountRetrieval_ErrorsConcatenate(t *testing.T) {
	c := AccountConfig{}

	err := c.ValidateForAccountRetrieval()
	require.Error(t, err)
	require.IsType(t, AccountConfigValidationError{}, err)
	e := err.(AccountConfigValidationError)
	require.Len(t, e.msgs, 6)
	require.ElementsMatch(t, e.msgs, []string{
		invalidSecretPathMsg,
		invalidSecretEnginePathMsg,
		invalidAddressMsg,
		invalidSecretVersionMsg,
		invalidUUIDMsg,
		invalidConfigVersionMsg,
	})
}

func TestAccountConfig_ValidateForAccountCreation_MinimumValidConfig(t *testing.T) {
	c := AccountConfig{
		VaultSecret: VaultSecretConfig{
			PathParams: PathParams{
				SecretEnginePath: "engine",
				SecretPath:       "path",
			},
		},
	}
	err := c.ValidateForAccountCreation()
	require.NoError(t, err)
}

func TestAccountConfig_ValidateForAccountCreation_ErrorsConcatenate(t *testing.T) {
	c := AccountConfig{}

	err := c.ValidateForAccountCreation()

	require.Error(t, err)
	require.IsType(t, AccountConfigValidationError{}, err)
	e := err.(AccountConfigValidationError)
	require.Len(t, e.msgs, 2)
	require.ElementsMatch(t, e.msgs, []string{
		invalidSecretPathMsg,
		invalidSecretEnginePathMsg,
	})
}
