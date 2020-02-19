package config

import (
	"errors"
	"fmt"
	"net/url"
)

const (
	invalidVaultUrl         = "vault must be a valid HTTP/HTTPS url"
	invalidAccountDirectory = "accountDirectory must be a valid file url"
	invalidAuthentication   = "authentication must contain roleId, secretId and approlePath OR only token"
	invalidCaCert           = "caCert must be a valid file url"
	invalidClientCert       = "clientCert must be a valid file url"
	invalidClientKey        = "clientKey must be a valid file url"
	invalidSecretLocation   = "secretEnginePath and secretPath must be set"
	invalidCAS              = "insecureSkipCAS and casValue cannot be set at the same time"
)

func (c VaultClients) Validate() error {
	for i, vc := range c {
		if err := vc.Validate(); err != nil {
			return fmt.Errorf("invalid config: array index %v: %v", i, err.Error())
		}
	}
	return nil
}

func (c VaultClient) Validate() error {
	if c.Vault == (url.URL{}) || c.Vault.Scheme == "" {
		return errors.New(invalidVaultUrl)
	}
	if c.AccountDirectory == (url.URL{}) || c.AccountDirectory.Scheme != "file" || c.AccountDirectory.Path == "" {
		return errors.New(invalidAccountDirectory)
	}
	if err := c.Authentication.Validate(); err != nil {
		return err
	}
	if err := c.TLS.Validate(); err != nil {
		return err
	}
	return nil
}

func (c VaultClientAuthentication) Validate() error {
	var (
		tokenIsSet       = c.Token.IsSet()
		roleIdIsSet      = c.RoleId.IsSet()
		secretIdIsSet    = c.SecretId.IsSet()
		approlePathIsSet = !(c.ApprolePath == "")
	)
	if roleIdIsSet && secretIdIsSet && approlePathIsSet {
		return nil
	}
	if tokenIsSet && !roleIdIsSet && !secretIdIsSet && !approlePathIsSet {
		return nil
	}
	return errors.New(invalidAuthentication)
}

func (c vaultClientTLS) Validate() error {
	if c.CaCert != (url.URL{}) && (c.CaCert.Scheme != "file" || c.CaCert.Path == "") {
		return errors.New(invalidCaCert)
	}
	if c.ClientCert != (url.URL{}) && (c.ClientCert.Scheme != "file" || c.ClientCert.Path == "") {
		return errors.New(invalidClientCert)
	}
	if c.ClientKey != (url.URL{}) && (c.ClientKey.Scheme != "file" || c.ClientKey.Path == "") {
		return errors.New(invalidClientKey)
	}
	return nil
}

func (c NewAccount) Validate() error {
	if c.Vault == (url.URL{}) || c.Vault.Scheme == "" {
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
