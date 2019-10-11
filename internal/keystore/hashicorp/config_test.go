package hashicorp

import (
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func minimumValidHashicorpAccountStoreConfig() HashicorpAccountStoreConfig {
	return HashicorpAccountStoreConfig{
		Wallets: []VaultConfig{minimumValidHashicorpWalletConfig()},
	}
}

func minimumValidHashicorpAccountStoreConfigForAccountCreation() HashicorpAccountStoreConfig {
	return HashicorpAccountStoreConfig{
		Wallets:          []VaultConfig{minimumValidHashicorpWalletConfig()},
		HashicorpAccount: minimumValidHashicorpAccountConfigForAccountCreation(),
	}
}

func minimumValidHashicorpWalletConfig() VaultConfig {
	return VaultConfig{
		VaultUrl:         "http://url:1",
		AccountConfigDir: "/path/to/dir",
	}
}

func minimumValidHashicorpAccountConfig() AccountConfig {
	return AccountConfig{
		SecretPath:       "secretpath",
		SecretVersion:    1,
		SecretEnginePath: "secretenginepath",
		Address:          acct1Data.addr,
	}
}

func minimumValidHashicorpAccountConfigForAccountCreation() AccountConfig {
	return AccountConfig{
		SecretPath:       "secretpath",
		SecretEnginePath: "secretenginepath",
	}
}

func TestHashicorpAccountStoreConfig_Validate(t *testing.T) {
	c := minimumValidHashicorpAccountStoreConfig()

	err := c.Validate()
	require.NoError(t, err)
}

func TestHashicorpAccountStoreConfig_Validate_AtLeastOneValidWalletConfigurationRequired(t *testing.T) {
	var err error

	c := minimumValidHashicorpAccountStoreConfig()
	c.Wallets = []VaultConfig{}
	err = c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), noWalletConfigMsg)

	w := minimumValidHashicorpWalletConfig()
	w.VaultUrl = ""
	c.Wallets = []VaultConfig{w}
	err = c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), invalidVaultUrlMsg)
}

func TestHashicorpAccountStoreConfig_Validate_AccountConfigurationIsOptionalButMustBeValid(t *testing.T) {
	var err error

	c := minimumValidHashicorpAccountStoreConfig()
	c.HashicorpAccount = AccountConfig{}
	err = c.Validate()
	require.NoError(t, err)

	c.HashicorpAccount = minimumValidHashicorpAccountConfig()
	err = c.Validate()
	require.NoError(t, err)

	c.HashicorpAccount.SecretPath = ""
	err = c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), invalidSecretPathMsg)
}

func TestHashicorpAccountStoreConfig_Validate_ErrorMsgsAreCombined(t *testing.T) {
	c := HashicorpAccountStoreConfig{}
	c.HashicorpAccount = minimumValidHashicorpAccountConfig()
	c.HashicorpAccount.SecretPath = ""

	contains := func(err error, msgs []string) bool {
		for _, msg := range msgs {
			if !strings.Contains(err.Error(), msg) {
				return false
			}
		}
		return true
	}

	want := []string{noWalletConfigMsg, invalidSecretPathMsg}

	err := c.Validate()

	require.Error(t, err)
	require.True(t, contains(err, want))
}

func TestHashicorpAccountStoreConfig_ValidateForAccountCreation(t *testing.T) {
	c := minimumValidHashicorpAccountStoreConfigForAccountCreation()

	err := c.ValidateForAccountCreation()
	require.NoError(t, err)
}

func TestHashicorpAccountStoreConfig_ValidateForAccountCreation_AtLeastOneValidWalletConfigurationRequired(t *testing.T) {
	var err error

	c := minimumValidHashicorpAccountStoreConfigForAccountCreation()
	c.Wallets = []VaultConfig{}
	err = c.ValidateForAccountCreation()
	require.Error(t, err)
	require.Contains(t, err.Error(), noWalletConfigMsg)

	w := minimumValidHashicorpWalletConfig()
	w.VaultUrl = ""
	c.Wallets = []VaultConfig{w}
	err = c.ValidateForAccountCreation()
	require.Error(t, err)
	require.Contains(t, err.Error(), invalidVaultUrlMsg)
}

func TestHashicorpAccountStoreConfig_ValidateForAccountCreation_AccountConfigurationRequired(t *testing.T) {
	c := minimumValidHashicorpAccountStoreConfigForAccountCreation()
	c.HashicorpAccount = AccountConfig{}

	contains := func(err error, msgs []string) bool {
		for _, msg := range msgs {
			if !strings.Contains(err.Error(), msg) {
				return false
			}
		}
		return true
	}

	want := []string{invalidSecretPathMsg, invalidSecretEnginePathMsg}

	err := c.ValidateForAccountCreation()

	require.Error(t, err)
	require.True(t, contains(err, want))
}

func TestHashicorpAccountStoreConfig_ValidateForAccountCreation_ErrorMsgsAreCombined(t *testing.T) {
	c := HashicorpAccountStoreConfig{}
	c.HashicorpAccount = minimumValidHashicorpAccountConfigForAccountCreation()
	c.HashicorpAccount.SecretPath = ""

	contains := func(err error, msgs []string) bool {
		for _, msg := range msgs {
			if !strings.Contains(err.Error(), msg) {
				return false
			}
		}
		return true
	}

	want := []string{noWalletConfigMsg, invalidSecretPathMsg}

	err := c.ValidateForAccountCreation()

	require.Error(t, err)
	require.True(t, contains(err, want))
}

func TestHashicorpWalletConfig_Validate(t *testing.T) {
	c := minimumValidHashicorpWalletConfig()

	err := c.Validate()
	require.NoError(t, err)
}

func TestHashicorpWalletConfig_Validate_VaultUrlRequired(t *testing.T) {
	c := minimumValidHashicorpWalletConfig()
	c.VaultUrl = ""

	err := c.Validate()

	require.Error(t, err)
	require.Contains(t, err.Error(), invalidVaultUrlMsg)
}

func TestHashicorpWalletConfig_Validate_AccountConfigDirRequired(t *testing.T) {
	c := minimumValidHashicorpWalletConfig()
	c.AccountConfigDir = ""

	err := c.Validate()

	require.Error(t, err)
	require.Contains(t, err.Error(), invalidAccountConfigDirMsg)
}

func TestHashicorpAccountConfig_Validate(t *testing.T) {
	c := minimumValidHashicorpAccountConfig()

	err := c.Validate()
	require.NoError(t, err)
}

func TestHashicorpAccountConfig_Validate_SecretPathRequired(t *testing.T) {
	c := minimumValidHashicorpAccountConfig()
	c.SecretPath = ""

	err := c.Validate()

	require.Error(t, err)
	require.Contains(t, err.Error(), invalidSecretPathMsg)
}

func TestHashicorpAccountConfig_Validate_SecretEnginePathRequired(t *testing.T) {
	c := minimumValidHashicorpAccountConfig()
	c.SecretEnginePath = ""

	err := c.Validate()

	require.Error(t, err)
	require.Contains(t, err.Error(), invalidSecretEnginePathMsg)
}

func TestHashicorpAccountConfig_Validate_SecretVersionRequiredAndMustBeGreaterThanZero(t *testing.T) {
	var err error

	c := minimumValidHashicorpAccountConfig()
	c.SecretVersion = 0
	err = c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), invalidSecretVersionMsg)

	c.SecretVersion = -1
	err = c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), invalidSecretVersionMsg)
}

func TestHashicorpAccountConfig_Validate_AddressRequiredAndMustBeValidHexAddress(t *testing.T) {
	var err error

	c := minimumValidHashicorpAccountConfig()
	c.Address = ""
	err = c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), invalidAddressMsg)

	c.Address = "notvalidhex"
	err = c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), invalidAddressMsg)
}

func TestHashicorpAccountConfig_Validate_ErrorMsgsAreCombined(t *testing.T) {
	c := AccountConfig{}

	contains := func(err error, msgs []string) bool {
		for _, msg := range msgs {
			if !strings.Contains(err.Error(), msg) {
				return false
			}
		}
		return true
	}

	want := []string{invalidSecretPathMsg, invalidSecretEnginePathMsg, invalidAddressMsg, invalidSecretVersionMsg}

	err := c.Validate()

	require.Error(t, err)
	require.True(t, contains(err, want))
}

func TestHashicorpAccountConfig_ValidateForAccountCreation(t *testing.T) {
	c := minimumValidHashicorpAccountConfigForAccountCreation()

	err := c.ValidateForAccountCreation()
	require.NoError(t, err)
}

func TestHashicorpAccountConfig_ValidateForAccountCreation_SecretPathRequired(t *testing.T) {
	c := minimumValidHashicorpAccountConfigForAccountCreation()
	c.SecretPath = ""

	err := c.ValidateForAccountCreation()

	require.Error(t, err)
	require.Contains(t, err.Error(), invalidSecretPathMsg)
}

func TestHashicorpAccountConfig_ValidateForAccountCreation_SecretEnginePathRequired(t *testing.T) {
	c := minimumValidHashicorpAccountConfigForAccountCreation()
	c.SecretEnginePath = ""

	err := c.ValidateForAccountCreation()

	require.Error(t, err)
	require.Contains(t, err.Error(), invalidSecretEnginePathMsg)
}

func TestHashicorpAccountConfig_ValidateForAccountCreation_ErrorMsgsAreCombined(t *testing.T) {
	c := AccountConfig{}

	contains := func(err error, msgs []string) bool {
		for _, msg := range msgs {
			if !strings.Contains(err.Error(), msg) {
				return false
			}
		}
		return true
	}

	want := []string{invalidSecretPathMsg, invalidSecretEnginePathMsg}

	err := c.ValidateForAccountCreation()

	require.Error(t, err)
	require.True(t, contains(err, want))
}
