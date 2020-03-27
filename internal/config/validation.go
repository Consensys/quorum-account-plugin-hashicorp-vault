package config

import (
	"errors"
)

const (
	InvalidVaultUrl         = "vault must be a valid HTTP/HTTPS url"
	InvalidAccountDirectory = "accountDirectory must be a valid file url"
	InvalidAuthentication   = "authentication must contain roleId, secretId and approlePath OR only token, and the given environment variables must be set"
	InvalidCaCert           = "caCert must be a valid file url"
	InvalidClientCert       = "clientCert must be a valid file url"
	InvalidClientKey        = "clientKey must be a valid file url"
	InvalidSecretLocation   = "secretEnginePath and secretPath must be set"
	InvalidCAS              = "insecureSkipCAS and casValue cannot be set at the same time"
)

func (c VaultClient) Validate() error {
	if c.Vault == nil || c.Vault.Scheme == "" {
		return errors.New(InvalidVaultUrl)
	}
	if c.AccountDirectory == nil || c.AccountDirectory.Scheme != "file" || (c.AccountDirectory.Host == "" && c.AccountDirectory.Path == "") {
		return errors.New(InvalidAccountDirectory)
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
	return errors.New(InvalidAuthentication)
}

func (c VaultClientTLS) validate() error {
	if c.CaCert != nil && (c.CaCert.Scheme != "file" || (c.CaCert.Host == "" && c.CaCert.Path == "")) {
		return errors.New(InvalidCaCert)
	}
	if c.ClientCert != nil && (c.ClientCert.Scheme != "file" || (c.ClientCert.Host == "" && c.ClientCert.Path == "")) {
		return errors.New(InvalidClientCert)
	}
	if c.ClientKey != nil && (c.ClientKey.Scheme != "file" || (c.ClientKey.Host == "" && c.ClientKey.Path == "")) {
		return errors.New(InvalidClientKey)
	}
	return nil
}

func (c NewAccount) Validate() error {
	if c.SecretEnginePath == "" || c.SecretPath == "" {
		return errors.New(InvalidSecretLocation)
	}
	if c.InsecureSkipCAS && c.CASValue != 0 {
		return errors.New(InvalidCAS)
	}
	return nil
}
