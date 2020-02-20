package config

import (
	"errors"
	"fmt"
)

const (
	invalidVaultUrl         = "vault must be a valid HTTP/HTTPS url"
	invalidAccountDirectory = "accountDirectory must be a valid file url"
	invalidAuthentication   = "authentication must contain roleId, secretId and approlePath OR only token, and the given environment variables must be set"
	invalidCaCert           = "caCert must be a valid file url"
	invalidClientCert       = "clientCert must be a valid file url"
	invalidClientKey        = "clientKey must be a valid file url"
	invalidSecretLocation   = "secretEnginePath and secretPath must be set"
	invalidCAS              = "insecureSkipCAS and casValue cannot be set at the same time"
)

func (c VaultClients) Validate() error {
	for i, vc := range c {
		if err := vc.validate(); err != nil {
			return fmt.Errorf("invalid config: array index %v: %v", i, err.Error())
		}
	}
	return nil
}

func (c VaultClient) validate() error {
	if c.Vault == nil || c.Vault.Scheme == "" {
		return errors.New(invalidVaultUrl)
	}
	if c.AccountDirectory == nil || c.AccountDirectory.Scheme != "file" || (c.AccountDirectory.Host == "" && c.AccountDirectory.Path == "") {
		return errors.New(invalidAccountDirectory)
	}
	if err := c.Authentication.validate(); err != nil {
		return err
	}
	if err := c.TLS.validate(); err != nil {
		return err
	}
	return nil
}

func (c VaultClientAuthentication) validate() error {
	var (
		tokenIsSet       = c.Token.IsSet()
		roleIdIsSet      = c.RoleId.IsSet()
		secretIdIsSet    = c.SecretId.IsSet()
		approlePathIsSet = !(c.ApprolePath == "")
	)
	if !tokenIsSet && roleIdIsSet && secretIdIsSet && approlePathIsSet {
		return nil
	}
	if tokenIsSet && !roleIdIsSet && !secretIdIsSet && !approlePathIsSet {
		return nil
	}
	return errors.New(invalidAuthentication)
}

func (c vaultClientTLS) validate() error {
	if c.CaCert != nil && (c.CaCert.Scheme != "file" || (c.CaCert.Host == "" && c.CaCert.Path == "")) {
		return errors.New(invalidCaCert)
	}
	if c.ClientCert != nil && (c.ClientCert.Scheme != "file" || (c.ClientCert.Host == "" && c.ClientCert.Path == "")) {
		return errors.New(invalidClientCert)
	}
	if c.ClientKey != nil && (c.ClientKey.Scheme != "file" || (c.ClientKey.Host == "" && c.ClientKey.Path == "")) {
		return errors.New(invalidClientKey)
	}
	return nil
}

func (c NewAccount) Validate() error {
	if c.Vault == nil || c.Vault.Scheme == "" {
		return errors.New(invalidVaultUrl)
	}
	if c.SecretEnginePath == "" || c.SecretPath == "" {
		return errors.New(invalidSecretLocation)
	}
	if c.InsecureSkipCAS && c.CASValue != 0 {
		return errors.New(invalidCAS)
	}
	return nil
}
