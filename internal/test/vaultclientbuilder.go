package test

import (
	"net/url"
	"testing"

	"github.com/ConsenSys/quorum-account-plugin-hashicorp-vault/internal/config"
	"github.com/stretchr/testify/assert"
)

type VaultClientBuilder struct {
	vaultUrl         string
	kvEngineName     string
	signerEngineName string
	acctDir          string
	unlock           []string
	tokenUrl         string
	roleIdUrl        string
	secretIdUrl      string
	approlePath      string
	caCertUrl        string
	clientCertUrl    string
	clientKeyUrl     string
}

func (b *VaultClientBuilder) WithVaultUrl(s string) *VaultClientBuilder {
	b.vaultUrl = s
	return b
}

func (b *VaultClientBuilder) WithKVEngineName(s string) *VaultClientBuilder {
	b.kvEngineName = s
	return b
}

func (b *VaultClientBuilder) WithSignerEngineName(s string) *VaultClientBuilder {
	b.signerEngineName = s
	return b
}

func (b *VaultClientBuilder) WithAccountDirectory(s string) *VaultClientBuilder {
	b.acctDir = s
	return b
}

func (b *VaultClientBuilder) WithUnlock(s []string) *VaultClientBuilder {
	b.unlock = s
	return b
}

func (b *VaultClientBuilder) WithTokenUrl(s string) *VaultClientBuilder {
	b.tokenUrl = s
	return b
}

func (b *VaultClientBuilder) WithRoleIdUrl(s string) *VaultClientBuilder {
	b.roleIdUrl = s
	return b
}

func (b *VaultClientBuilder) WithSecretIdUrl(s string) *VaultClientBuilder {
	b.secretIdUrl = s
	return b
}

func (b *VaultClientBuilder) WithApprolePath(s string) *VaultClientBuilder {
	b.approlePath = s
	return b
}

func (b *VaultClientBuilder) WithCaCertUrl(s string) *VaultClientBuilder {
	b.caCertUrl = s
	return b
}

func (b *VaultClientBuilder) WithClientCertUrl(s string) *VaultClientBuilder {
	b.clientCertUrl = s
	return b
}

func (b *VaultClientBuilder) WithClientKeyUrl(s string) *VaultClientBuilder {
	b.clientKeyUrl = s
	return b
}

func (b *VaultClientBuilder) Build(t *testing.T) config.VaultClient {
	var err error

	var vault *url.URL
	if b.vaultUrl != "" {
		vault, err = url.Parse(b.vaultUrl)
		assert.NoError(t, err)
	}

	var acctDir *url.URL
	if b.acctDir != "" {
		acctDir, err = url.Parse(b.acctDir)
		assert.NoError(t, err)
	}

	var tokenEnv config.EnvironmentVariable
	if b.tokenUrl != "" {
		token, err := url.Parse(b.tokenUrl)
		assert.NoError(t, err)
		tokenEnv = config.EnvironmentVariable(*token)
	}

	var roleIdEnv config.EnvironmentVariable
	if b.roleIdUrl != "" {
		roleId, err := url.Parse(b.roleIdUrl)
		assert.NoError(t, err)
		roleIdEnv = config.EnvironmentVariable(*roleId)
	}

	var secretIdEnv config.EnvironmentVariable
	if b.secretIdUrl != "" {
		secretId, err := url.Parse(b.secretIdUrl)
		assert.NoError(t, err)
		secretIdEnv = config.EnvironmentVariable(*secretId)
	}

	var caCert *url.URL
	if b.caCertUrl != "" {
		caCert, err = url.Parse(b.caCertUrl)
		assert.NoError(t, err)
	}

	var clientCert *url.URL
	if b.clientCertUrl != "" {
		clientCert, err = url.Parse(b.clientCertUrl)
		assert.NoError(t, err)
	}

	var clientKey *url.URL
	if b.clientKeyUrl != "" {
		clientKey, err = url.Parse(b.clientKeyUrl)
		assert.NoError(t, err)
	}

	return config.VaultClient{
		VaultClientBase: config.VaultClientBase{
			Vault:            vault,
			AccountDirectory: acctDir,
			Authentication: config.VaultClientAuthentication{
				Token:       &tokenEnv,
				RoleId:      &roleIdEnv,
				SecretId:    &secretIdEnv,
				ApprolePath: b.approlePath,
			},
			TLS: config.VaultClientTLS{
				CaCert:     caCert,
				ClientCert: clientCert,
				ClientKey:  clientKey,
			},
		},
		KVEngineName:           b.kvEngineName,
		QuorumSignerEngineName: b.signerEngineName,
		Unlock:                 b.unlock,
	}
}
