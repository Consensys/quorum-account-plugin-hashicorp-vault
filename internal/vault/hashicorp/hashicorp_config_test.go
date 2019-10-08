package hashicorp

import (
	"strings"
	"testing"
)

func minimumValidHashicorpAccountStoreConfig() HashicorpAccountStoreConfig {
	return HashicorpAccountStoreConfig{
		Wallets: []HashicorpWalletConfig{minimumValidHashicorpWalletConfig()},
	}
}

func minimumValidHashicorpAccountStoreConfigForAccountCreation() HashicorpAccountStoreConfig {
	return HashicorpAccountStoreConfig{
		Wallets:          []HashicorpWalletConfig{minimumValidHashicorpWalletConfig()},
		HashicorpAccount: minimumValidHashicorpAccountConfigForAccountCreation(),
	}
}

func minimumValidHashicorpWalletConfig() HashicorpWalletConfig {
	return HashicorpWalletConfig{
		VaultUrl:         "http://url:1",
		AccountConfigDir: "/path/to/dir",
	}
}

func minimumValidHashicorpAccountConfig() HashicorpAccountConfig {
	return HashicorpAccountConfig{
		SecretPath:       "secretpath",
		SecretVersion:    1,
		SecretEnginePath: "secretenginepath",
		Address:          acct1.addr,
	}
}

func minimumValidHashicorpAccountConfigForAccountCreation() HashicorpAccountConfig {
	return HashicorpAccountConfig{
		SecretPath:       "secretpath",
		SecretEnginePath: "secretenginepath",
	}
}

func TestHashicorpAccountStoreConfig_Validate(t *testing.T) {
	c := minimumValidHashicorpAccountStoreConfig()

	if err := c.Validate(); err != nil {
		t.Fatal("config should be valid")
	}
}

func TestHashicorpAccountStoreConfig_Validate_AtLeastOneValidWalletConfigurationRequired(t *testing.T) {
	c := minimumValidHashicorpAccountStoreConfig()

	c.Wallets = []HashicorpWalletConfig{}

	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), noWalletConfigMsg) {
		t.Fatalf("want error containing: %v, got: %v", noWalletConfigMsg, err)
	}

	w := minimumValidHashicorpWalletConfig()
	w.VaultUrl = ""
	c.Wallets = []HashicorpWalletConfig{w}

	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), invalidVaultUrlMsg) {
		t.Fatalf("want error containing: %v, got: %v", invalidVaultUrlMsg, err)
	}
}

func TestHashicorpAccountStoreConfig_Validate_AccountConfigurationIsOptionalButMustBeValid(t *testing.T) {
	c := minimumValidHashicorpAccountStoreConfig()
	c.HashicorpAccount = HashicorpAccountConfig{}

	if err := c.Validate(); err != nil {
		t.Fatal("config should be valid")
	}

	c.HashicorpAccount = minimumValidHashicorpAccountConfig()

	if err := c.Validate(); err != nil {
		t.Fatal("config should be valid")
	}

	c.HashicorpAccount.SecretPath = ""

	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), invalidSecretPathMsg) {
		t.Fatalf("want error containing: %v, got: %v", invalidSecretPathMsg, err)
	}
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

	if err := c.Validate(); err == nil || !contains(err, want) {
		t.Fatalf("want error containing: %v\ngot: %v", want, err)
	}
}

func TestHashicorpAccountStoreConfig_ValidateForAccountCreation(t *testing.T) {
	c := minimumValidHashicorpAccountStoreConfigForAccountCreation()

	if err := c.ValidateForAccountCreation(); err != nil {
		t.Fatal("config should be valid")
	}
}

func TestHashicorpAccountStoreConfig_ValidateForAccountCreation_AtLeastOneValidWalletConfigurationRequired(t *testing.T) {
	c := minimumValidHashicorpAccountStoreConfigForAccountCreation()

	c.Wallets = []HashicorpWalletConfig{}

	if err := c.ValidateForAccountCreation(); err == nil || !strings.Contains(err.Error(), noWalletConfigMsg) {
		t.Fatalf("want error containing: %v, got: %v", noWalletConfigMsg, err)
	}

	w := minimumValidHashicorpWalletConfig()
	w.VaultUrl = ""
	c.Wallets = []HashicorpWalletConfig{w}

	if err := c.ValidateForAccountCreation(); err == nil || !strings.Contains(err.Error(), invalidVaultUrlMsg) {
		t.Fatalf("want error containing: %v, got: %v", invalidVaultUrlMsg, err)
	}
}

func TestHashicorpAccountStoreConfig_ValidateForAccountCreation_AccountConfigurationRequired(t *testing.T) {
	c := minimumValidHashicorpAccountStoreConfigForAccountCreation()
	c.HashicorpAccount = HashicorpAccountConfig{}

	contains := func(err error, msgs []string) bool {
		for _, msg := range msgs {
			if !strings.Contains(err.Error(), msg) {
				return false
			}
		}
		return true
	}

	want := []string{invalidSecretPathMsg, invalidSecretEnginePathMsg}

	if err := c.ValidateForAccountCreation(); err == nil || !contains(err, want) {
		t.Fatalf("want error containing: %v\ngot: %v", want, err)
	}
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

	if err := c.ValidateForAccountCreation(); err == nil || !contains(err, want) {
		t.Fatalf("want error containing: %v\ngot: %v", want, err)
	}
}

func TestHashicorpWalletConfig_Validate(t *testing.T) {
	c := minimumValidHashicorpWalletConfig()

	if err := c.Validate(); err != nil {
		t.Fatal("config should be valid")
	}
}

func TestHashicorpWalletConfig_Validate_VaultUrlRequired(t *testing.T) {
	c := minimumValidHashicorpWalletConfig()

	c.VaultUrl = ""

	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), invalidVaultUrlMsg) {
		t.Fatalf("want error containing: %v, got: %v", invalidVaultUrlMsg, err)
	}
}

func TestHashicorpWalletConfig_Validate_AccountConfigDirRequired(t *testing.T) {
	c := minimumValidHashicorpWalletConfig()

	c.AccountConfigDir = ""

	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), invalidAccountConfigDirMsg) {
		t.Fatalf("want error containing: %v, got: %v", invalidAccountConfigDirMsg, err)
	}
}

func TestHashicorpAccountConfig_Validate(t *testing.T) {
	c := minimumValidHashicorpAccountConfig()

	if err := c.Validate(); err != nil {
		t.Fatal("config should be valid")
	}
}

func TestHashicorpAccountConfig_Validate_SecretPathRequired(t *testing.T) {
	c := minimumValidHashicorpAccountConfig()

	c.SecretPath = ""

	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), invalidSecretPathMsg) {
		t.Fatalf("want error containing: %v, got: %v", invalidSecretPathMsg, err)
	}
}

func TestHashicorpAccountConfig_Validate_SecretEnginePathRequired(t *testing.T) {
	c := minimumValidHashicorpAccountConfig()

	c.SecretEnginePath = ""

	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), invalidSecretEnginePathMsg) {
		t.Fatalf("want error containing: %v, got: %v", invalidSecretEnginePathMsg, err)
	}
}

func TestHashicorpAccountConfig_Validate_SecretVersionRequiredAndMustBeGreaterThanZero(t *testing.T) {
	c := minimumValidHashicorpAccountConfig()

	c.SecretVersion = 0

	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), invalidSecretVersionMsg) {
		t.Fatalf("want error containing: %v, got: %v", invalidSecretVersionMsg, err)
	}

	c.SecretVersion = -1

	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), invalidSecretVersionMsg) {
		t.Fatalf("want error containing: %v, got: %v", invalidSecretVersionMsg, err)
	}
}

func TestHashicorpAccountConfig_Validate_AddressRequiredAndMustBeValidHexAddress(t *testing.T) {
	c := minimumValidHashicorpAccountConfig()

	c.Address = ""

	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), invalidAddressMsg) {
		t.Fatalf("want error containing: %v, got: %v", invalidAddressMsg, err)
	}

	c.Address = "notvalidhex"

	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), invalidAddressMsg) {
		t.Fatalf("want error containing: %v, got: %v", invalidAddressMsg, err)
	}
}

func TestHashicorpAccountConfig_Validate_ErrorMsgsAreCombined(t *testing.T) {
	c := HashicorpAccountConfig{}

	contains := func(err error, msgs []string) bool {
		for _, msg := range msgs {
			if !strings.Contains(err.Error(), msg) {
				return false
			}
		}
		return true
	}

	want := []string{invalidSecretPathMsg, invalidSecretEnginePathMsg, invalidAddressMsg, invalidSecretVersionMsg}

	if err := c.Validate(); err == nil || !contains(err, want) {
		t.Fatalf("want error containing: %v\ngot: %v", want, err)
	}
}

func TestHashicorpAccountConfig_ValidateForAccountCreation(t *testing.T) {
	c := minimumValidHashicorpAccountConfigForAccountCreation()

	if err := c.ValidateForAccountCreation(); err != nil {
		t.Fatal("config should be valid")
	}
}

func TestHashicorpAccountConfig_ValidateForAccountCreation_SecretPathRequired(t *testing.T) {
	c := minimumValidHashicorpAccountConfigForAccountCreation()

	c.SecretPath = ""

	if err := c.ValidateForAccountCreation(); err == nil || !strings.Contains(err.Error(), invalidSecretPathMsg) {
		t.Fatalf("want error containing: %v, got: %v", invalidSecretPathMsg, err)
	}
}

func TestHashicorpAccountConfig_ValidateForAccountCreation_SecretEnginePathRequired(t *testing.T) {
	c := minimumValidHashicorpAccountConfigForAccountCreation()

	c.SecretEnginePath = ""

	if err := c.ValidateForAccountCreation(); err == nil || !strings.Contains(err.Error(), invalidSecretEnginePathMsg) {
		t.Fatalf("want error containing: %v, got: %v", invalidSecretEnginePathMsg, err)
	}
}

func TestHashicorpAccountConfig_ValidateForAccountCreation_ErrorMsgsAreCombined(t *testing.T) {
	c := HashicorpAccountConfig{}

	contains := func(err error, msgs []string) bool {
		for _, msg := range msgs {
			if !strings.Contains(err.Error(), msg) {
				return false
			}
		}
		return true
	}

	want := []string{invalidSecretPathMsg, invalidSecretEnginePathMsg}

	if err := c.ValidateForAccountCreation(); err == nil || !contains(err, want) {
		t.Fatalf("want error containing: %v\ngot: %v", want, err)
	}
}
