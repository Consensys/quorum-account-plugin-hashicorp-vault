package config

import (
	"errors"
	"net/url"
)

const (
	InvalidVaultUrl            = "vault must be a valid HTTP/HTTPS url"
	InvalidSecretEngine        = "either kvEngineName or quorumSignerEngineName must be set"
	UnlockNotSupported         = "unlock is not supported when using quorumSignerEngine"
	InvalidAccountDirectory    = "accountDirectory must be a valid absolute file url"
	InvalidAuthentication      = "authentication must contain roleId, secretId and approlePath OR only token, and the given environment variables must be set"
	InvalidCaCert              = "caCert must be a valid absolute file url"
	InvalidClientCert          = "clientCert must be a valid absolute file url"
	InvalidClientKey           = "clientKey must be a valid absolute file url"
	InvalidSecretName          = "secretName must be set"
	InvalidOverwriteProtection = "currentVersion and insecureDisable cannot both be set"
)

func (c VaultClientBase) Validate() error {
	if c.Vault == nil || c.Vault.Scheme == "" {
		return errors.New(InvalidVaultUrl)
	}
	if c.AccountDirectory == nil || !isValidAbsFileUrl(c.AccountDirectory) {
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

func (c VaultClient) Validate() error {
	if err := c.VaultClientBase.Validate(); err != nil {
		return err
	}
	if c.KVEngineName == "" && c.QuorumSignerEngineName == "" {
		return errors.New(InvalidSecretEngine)
	}
	if c.KVEngineName != "" && c.QuorumSignerEngineName != "" {
		return errors.New(InvalidSecretEngine)
	}
	if c.QuorumSignerEngineName != "" && len(c.Unlock) != 0 {
		return errors.New(UnlockNotSupported)
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
	if c.CaCert == nil || (c.CaCert.String() != "" && !isValidAbsFileUrl(c.CaCert)) {
		return errors.New(InvalidCaCert)
	}
	if c.ClientCert == nil || (c.ClientCert.String() != "" && !isValidAbsFileUrl(c.ClientCert)) {
		return errors.New(InvalidClientCert)
	}
	if c.ClientKey == nil || (c.ClientKey.String() != "" && !isValidAbsFileUrl(c.ClientKey)) {
		return errors.New(InvalidClientKey)
	}
	return nil
}

func (c NewAccount) Validate() error {
	if c.SecretName == "" {
		return errors.New(InvalidSecretName)
	}
	if err := c.OverwriteProtection.validate(); err != nil {
		return err
	}
	return nil
}

func (c OverwriteProtection) validate() error {
	if c.InsecureDisable && c.CurrentVersion != 0 {
		return errors.New(InvalidOverwriteProtection)
	}
	return nil
}

func isValidAbsFileUrl(u *url.URL) bool {
	return u.Scheme == "file" && u.Host == "" && u.Path != ""
}
