package config

import (
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/utils"

	//"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

const (
	HashiScheme = "hashivlt"

	invalidSecretPathMsg       = "SecretPath must be provided"
	invalidSecretEnginePathMsg = "SecretEnginePath must be provided"
	invalidAddressMsg          = "Address must be provided and be a valid hex address"
	invalidSecretVersionMsg    = "SecretVersion must be specified and be greater than zero"
	invalidUUIDMsg             = "Id must be specified"
	invalidConfigVersionMsg    = "Config version must be specified and be greater than zero"
)

// AccountConfig contains the config for a single Vault-stored account
type AccountConfig struct {
	// Address is the hex-encoded Ethereum address of the account
	Address     string            `json:"address"`
	VaultSecret VaultSecretConfig `json:"vaultsecret"`
	Id          string            `json:"id"`
	// Version indicates the format of the config
	Version int `json:"version"`
}

// VaultSecretConfig contains the Vault-related config for a Vault-stored account
type VaultSecretConfig struct {
	PathParams PathParams `json:"pathparams"`
	// AuthID indicates which of the account manager's configured authentication methods should be used when retrieving the account from the Vault
	AuthID string `json:"authid"`
	// InsecureSkipCas indicates whether Check-and-Set checks should be skipped when writing to the Vault.  Using CAS reduces the risk of accidental writes to the Vault.  This field is not marshalled to json for the account config files and so can only be configured when using the CLI flags during account creation.
	InsecureSkipCas bool `json:"-"`
	// CasValue specifies the Check-and-Set value when using CAS.  Using CAS reduces the risk of accidental writes to the Vault.  This field is not marshalled to json for the account config files and so can only be configured when using the CLI flags during account creation.
	CasValue uint64 `json:"-"`
}

// PathParams contains the Vault location-related config for a Vault-stored account
type PathParams struct {
	SecretEnginePath string `json:"secretenginepath"`
	SecretPath       string `json:"secretpath"`
	SecretVersion    int64  `json:"secretversion"`
}

// ValidateForAccountRetrieval checks the config is valid and has the necessary fields populated to retrieve the account from a Vault.
func (c AccountConfig) ValidateForAccountRetrieval() error {
	return c.validate(false)
}

// ValidateForAccountCreation checks the config is valid and has the necessary fields populated to create and write an account to a Vault.
//
// This should not be used to validate configs intended for account retrieval.
func (c AccountConfig) ValidateForAccountCreation() error {
	return c.validate(true)
}

func (c AccountConfig) validate(isAcctCreation bool) error {
	var errs []string

	if c.VaultSecret.PathParams.SecretPath == "" {
		errs = append(errs, invalidSecretPathMsg)
	}
	if c.VaultSecret.PathParams.SecretEnginePath == "" {
		errs = append(errs, invalidSecretEnginePathMsg)
	}

	if !isAcctCreation {
		if c.Address == "" || !common.IsHexAddress(c.Address) {
			errs = append(errs, invalidAddressMsg)
		}
		if c.VaultSecret.PathParams.SecretVersion <= 0 {
			errs = append(errs, invalidSecretVersionMsg)
		}
		if c.Id == "" {
			errs = append(errs, invalidUUIDMsg)
		}
		if c.Version <= 0 {
			errs = append(errs, invalidConfigVersionMsg)
		}
	}

	if len(errs) > 0 {
		return AccountConfigValidationError{msgs: errs}
	}

	return nil
}

type AccountConfigValidationError struct {
	msgs []string
}

func (e AccountConfigValidationError) Error() string {
	return fmt.Sprintf("Invalid Hashicorp Vault-stored account config:\n%v", strings.Join(e.msgs, "\n"))
}

// ToAccount creates an accounts.Account from the provided AccountConfig and acct configfile path
func ToAccount(c AccountConfig, vaultUrl string) (accounts.Account, error) {
	vaultAddr, err := utils.ToUrl(vaultUrl)
	if err != nil {
		return accounts.Account{}, err
	}

	walletPath := fmt.Sprintf(
		"%v/v1/%v/data/%v?version=%v#addr=%v",
		vaultAddr.Path,
		c.VaultSecret.PathParams.SecretEnginePath,
		c.VaultSecret.PathParams.SecretPath,
		c.VaultSecret.PathParams.SecretVersion,
		c.Address,
	)

	if c.VaultSecret.AuthID != "" {
		walletPath = fmt.Sprintf("%v@%v", c.VaultSecret.AuthID, walletPath)
	}

	return accounts.Account{
		Address: common.HexToAddress(c.Address),
		URL:     accounts.URL{Scheme: HashiScheme, Path: walletPath},
	}, nil
}
