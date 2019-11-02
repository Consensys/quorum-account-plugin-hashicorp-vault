package config

import (
	"fmt"
	"strings"
)

const (
	noVaultConfigMsg           = "No Hashicorp Vault config provided"
	invalidVaultUrlMsg         = "URL must be provided"
	invalidAccountConfigDirMsg = "AccountConfigDir must be provided"
	invalidAuthIDMsg           = "the same AuthID cannot be used multiple times"
)

// PluginAccountManagerConfig contains the config for one or more Vault account stores
type PluginAccountManagerConfig struct {
	Vaults []VaultConfig `toml:",omitempty" json:"vaults,omitempty"`
}

// VaultConfig contains the config to use a Vault server as an account store
type VaultConfig struct {
	URL              string      `toml:",omitempty" json:"url,omitempty"`
	TLS              TLS         `toml:",omitempty" json:"tls,omitempty"`
	AccountConfigDir string      `toml:",omitempty" json:"accountConfigDir,omitempty"`
	Unlock           string      `toml:",omitempty" json:"unlock,omitempty"`
	Auth             []VaultAuth `toml:",omitempty" json:"auth,omitempty"`
}

// TLS contains the config to use a TLS-enabled Vault server as an account store
type TLS struct {
	CaCert     string `toml:",omitempty" json:"caCert,omitempty"`
	ClientCert string `toml:",omitempty" json:"clientCert,omitempty"`
	ClientKey  string `toml:",omitempty" json:"clientKey,omitempty"`
}

// VaultAuth contains the config to authenticate the account manager with a Vault server using an existing AppRole authentication method.  ApprolePath is the name of the AppRole auth method to use.  The account manager will login to the auth method using credentials provided as environment variables.   AuthID is optional and specifies a prefix to be applied to the environment variables names, thereby allowing multiple VaultAuths to be configured, each using their own set of login credentials.
type VaultAuth struct {
	AuthID      string `toml:",omitempty" json:"authID,omitempty"`
	ApprolePath string `toml:",omitempty" json:"approlePath,omitempty"`
}

// Validate checks the config is valid and has the necessary fields populated
func (c PluginAccountManagerConfig) Validate() error {
	var errs []string

	if len(c.Vaults) == 0 {
		errs = append(errs, noVaultConfigMsg)
	}

	for i, v := range c.Vaults {
		if v.URL == "" {
			errs = append(errs, fmt.Sprintf("Vaults[%v]: %v", i, invalidVaultUrlMsg))
		}
		if v.AccountConfigDir == "" {
			errs = append(errs, fmt.Sprintf("Vaults[%v]: %v", i, invalidAccountConfigDirMsg))
		}
		// validate that no AuthID has been configured more than once
		usedAuthIDs := make(map[string]struct{})
		for j, a := range v.Auth {
			if _, ok := usedAuthIDs[a.AuthID]; ok {
				// the authID has already been used
				errs = append(errs, fmt.Sprintf("Vaults[%v]: Auth[%v]: %v", i, j, invalidAuthIDMsg))
			} else {
				usedAuthIDs[a.AuthID] = struct{}{}
			}
		}
	}

	if len(errs) > 0 {
		return PluginAccountManagerConfigValidationError{msgs: errs}
	}

	return nil
}

type PluginAccountManagerConfigValidationError struct {
	msgs []string
}

func (e PluginAccountManagerConfigValidationError) Error() string {
	return fmt.Sprintf("Invalid Hashicorp Vault account manager plugin config:\n%v", strings.Join(e.msgs, "\n"))
}
