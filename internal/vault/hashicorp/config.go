package hashicorp

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault"
	"io"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

const (
	noWalletConfigMsg = "No Hashicorp Vault wallet config provided"

	invalidVaultUrlMsg         = "VaultUrl must be provided"
	invalidAccountConfigDirMsg = "AccountConfigDir must be provided"

	invalidSecretPathMsg       = "SecretPath must be provided"
	invalidSecretEnginePathMsg = "SecretEnginePath must be provided"
	invalidAddressMsg          = "Address must be provided and be a valid hex address"
	invalidSecretVersionMsg    = "SecretVersion must be specified and be greater than zero"
)

type HashicorpAccountStoreConfig struct {
	Wallets          []HashicorpWalletConfig `toml:",omitempty"`
	HashicorpAccount HashicorpAccountConfig  `toml:"-"` // HashicorpAccount defines the secret to write to during account creation
}

func (c HashicorpAccountStoreConfig) Validate() error {
	return c.validate(false)
}

func (c HashicorpAccountStoreConfig) ValidateForAccountCreation() error {
	return c.validate(true)
}

func (c HashicorpAccountStoreConfig) validate(isAcctCreation bool) error {
	var errs []string

	if len(c.Wallets) == 0 {
		errs = append(errs, noWalletConfigMsg)
	}

	for i, w := range c.Wallets {
		if err := w.Validate(); err != nil {
			errs = append(errs, fmt.Sprintf("Wallets[%v]: %v", i, err.Error()))
		}
	}

	if isAcctCreation {
		if err := c.HashicorpAccount.ValidateForAccountCreation(); err != nil {
			errs = append(errs, err.Error())
		}
	} else {
		// only validate if account config has been provided (i.e. allow account config to not be defined at startup)
		if c.HashicorpAccount != (HashicorpAccountConfig{}) {
			if err := c.HashicorpAccount.Validate(); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("Invalid HashicorpAccountStore config:\n%v", strings.Join(errs, "\n"))
	}

	return nil
}

type HashicorpWalletConfig struct {
	VaultUrl         string `toml:",omitempty"`
	ApprolePath      string `toml:",omitempty"`
	CaCert           string `toml:",omitempty"`
	ClientCert       string `toml:",omitempty"`
	ClientKey        string `toml:",omitempty"`
	AccountConfigDir string `toml:",omitempty"`
	Unlock           string `toml:",omitempty"`
	AuthorizationID  string `toml:",omitempty"`
}

func (c HashicorpWalletConfig) Validate() error {
	var errs []string

	if c.VaultUrl == "" {
		errs = append(errs, invalidVaultUrlMsg)
	}

	if c.AccountConfigDir == "" {
		errs = append(errs, invalidAccountConfigDirMsg)
	}

	if len(errs) > 0 {
		return fmt.Errorf("Invalid Hashicorp Vault wallet config:\n%v", strings.Join(errs, "\n"))
	}

	return nil
}

type HashicorpAccountConfig struct {
	SecretPath       string `json:"secretpath,omitempty"`
	SecretVersion    int64  `json:"secretversion,omitempty"`
	SecretEnginePath string `json:"secretenginepath,omitempty"`
	Address          string `json:"address,omitempty"`
	SkipCas          bool   `json:"-"` // is not marshalled to json - only populated by CLI flags during account creation
	CasValue         uint64 `json:"-"` // is not marshalled to json - only populated by CLI flags during account creation
	secretUrl        string `json:"-"` // is not marshalled to json - used only to keep track of the HTTP url of the new secret during account creation
}

// Validate checks that the HashicorpWalletConfig has the minimum fields defined to be a valid configuration.  If the configuration is invalid an error is returned describing which fields have not been defined otherwise nil is returned.
//
// This should be used to validate configs intended to be used for retrieving from a Vault (i.e. in normal node operation).  For configs intended to be used for writing to a Vault use ValidateForAccountCreation.
func (c HashicorpAccountConfig) Validate() error {
	return c.validate(false)
}

// ValidateForAccountCreation checks that the HashicorpWalletConfig has the minimum fields defined to be a valid configuration, ignoring the version fields.  If the configuration is invalid an error is returned describing which fields have not been defined otherwise nil is returned.
//
// This should be used over Validate when validating configs intended to be used to write to the vault (i.e. in new account creation) as it is not necessary to specify the version number in these cases.
//
// It is not recommended to use ValidateForAccountCreation when validating configs intended to retrieve from a Vault as this will allow secrets to be configured with version=0 (i.e. always retrieve the latest version of a secret).  This is to protect against secrets being updated and a node then being unable to access the original accounts it was configured with because the wallet is now only capable of retrieving the latest version of the secret.
func (c HashicorpAccountConfig) ValidateForAccountCreation() error {
	return c.validate(true)
}

func (c HashicorpAccountConfig) validate(skipAddrAndVersion bool) error {
	var errs []string

	if c.SecretPath == "" {
		errs = append(errs, invalidSecretPathMsg)
	}

	if c.SecretEnginePath == "" {
		errs = append(errs, invalidSecretEnginePathMsg)
	}

	if !skipAddrAndVersion {
		if c.Address == "" || !common.IsHexAddress(c.Address) {
			errs = append(errs, invalidAddressMsg)
		}

		if c.SecretVersion <= 0 {
			errs = append(errs, invalidSecretVersionMsg)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("Invalid Hashicorp Vault account config:\n%v", strings.Join(errs, "\n"))
	}

	return nil
}

func (c HashicorpAccountConfig) AsAccount(urlPath string) *accounts.Account {
	return &accounts.Account{Address: common.HexToAddress(c.Address), URL: accounts.URL{Scheme: AcctScheme, Path: urlPath}}
}

type JsonAccountConfigUnmarshaller struct{}

func (JsonAccountConfigUnmarshaller) Unmarshal(r io.Reader) (vault.ValidatableAccountGetterConfig, error) {
	acctConfig := HashicorpAccountConfig{}
	if err := json.NewDecoder(r).Decode(&acctConfig); err != nil {
		return nil, err
	}

	return acctConfig, nil
}
