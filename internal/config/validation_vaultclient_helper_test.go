package config

import (
	"github.com/stretchr/testify/assert"
	"net/url"
	"os"
	"testing"
)

const (
	MY_TOKEN     = "MY_TOKEN"
	MY_ROLE_ID   = "MY_ROLE_ID"
	MY_SECRET_ID = "MY_SECRET_ID"
)

type environmentHelper struct{}

type vaultClientsBuilder struct {
	clients []VaultClient
}

type vaultClientBuilder struct {
	vaultUrl      string
	acctDir       string
	unlock        []string
	tokenUrl      string
	roleIdUrl     string
	secretIdUrl   string
	approlePath   string
	caCertUrl     string
	clientCertUrl string
	clientKeyUrl  string
}

func (environmentHelper) setToken() {
	os.Setenv(MY_TOKEN, "tokenval")
}

func (environmentHelper) setRoleID() {
	os.Setenv(MY_ROLE_ID, "roleidval")
}

func (environmentHelper) setSecretID() {
	os.Setenv(MY_SECRET_ID, "secretidval")
}

func (environmentHelper) unsetAll() {
	os.Unsetenv(MY_TOKEN)
	os.Unsetenv(MY_ROLE_ID)
	os.Unsetenv(MY_SECRET_ID)
}

func (b *vaultClientsBuilder) vaultClient(client VaultClient) *vaultClientsBuilder {
	b.clients = append(b.clients, client)
	return b
}

func (b *vaultClientsBuilder) build() VaultClients {
	return b.clients
}

func (b *vaultClientBuilder) withVaultUrl(s string) *vaultClientBuilder {
	b.vaultUrl = s
	return b
}

func (b *vaultClientBuilder) withAccountDirectory(s string) *vaultClientBuilder {
	b.acctDir = s
	return b
}

func (b *vaultClientBuilder) withUnlock(s []string) *vaultClientBuilder {
	b.unlock = s
	return b
}

func (b *vaultClientBuilder) withTokenUrl(s string) *vaultClientBuilder {
	b.tokenUrl = s
	return b
}

func (b *vaultClientBuilder) withRoleIdUrl(s string) *vaultClientBuilder {
	b.roleIdUrl = s
	return b
}

func (b *vaultClientBuilder) withSecretIdUrl(s string) *vaultClientBuilder {
	b.secretIdUrl = s
	return b
}

func (b *vaultClientBuilder) withApprolePath(s string) *vaultClientBuilder {
	b.approlePath = s
	return b
}

func (b *vaultClientBuilder) withCaCertUrl(s string) *vaultClientBuilder {
	b.caCertUrl = s
	return b
}

func (b *vaultClientBuilder) withClientCertUrl(s string) *vaultClientBuilder {
	b.clientCertUrl = s
	return b
}

func (b *vaultClientBuilder) withClientKeyUrl(s string) *vaultClientBuilder {
	b.clientKeyUrl = s
	return b
}

func (b *vaultClientBuilder) build(t *testing.T) VaultClient {
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

	var tokenEnv environmentVariable
	if b.tokenUrl != "" {
		token, err := url.Parse(b.tokenUrl)
		assert.NoError(t, err)
		tokenEnv = environmentVariable(*token)
	}

	var roleIdEnv environmentVariable
	if b.roleIdUrl != "" {
		roleId, err := url.Parse(b.roleIdUrl)
		assert.NoError(t, err)
		roleIdEnv = environmentVariable(*roleId)
	}

	var secretIdEnv environmentVariable
	if b.secretIdUrl != "" {
		secretId, err := url.Parse(b.secretIdUrl)
		assert.NoError(t, err)
		secretIdEnv = environmentVariable(*secretId)
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

	return VaultClient{
		Vault:            vault,
		AccountDirectory: acctDir,
		Unlock:           b.unlock,
		Authentication: VaultClientAuthentication{
			Token:       &tokenEnv,
			RoleId:      &roleIdEnv,
			SecretId:    &secretIdEnv,
			ApprolePath: b.approlePath,
		},
		TLS: vaultClientTLS{
			CaCert:     caCert,
			ClientCert: clientCert,
			ClientKey:  clientKey,
		},
	}
}
