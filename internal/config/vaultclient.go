package config

import (
	"encoding/json"
	"net/url"
	"os"
)

type VaultClients []VaultClient

type VaultClient struct {
	Vault            url.URL
	AccountDirectory url.URL
	Unlock           []string
	Authorization    vaultClientAuthorization
	TLS              vaultClientTLS
}

type environmentVariable url.URL

func (e environmentVariable) get() string {
	u := url.URL(e)
	return os.Getenv(u.Path)
}

func (e environmentVariable) isSet() bool {
	u := url.URL(e)
	if u.Path == "" {
		return false
	}
	_, b := os.LookupEnv(u.Path)
	return b
}

type vaultClientAuthorization struct {
	Token       environmentVariable
	RoleId      environmentVariable
	SecretId    environmentVariable
	ApprolePath string
}

type vaultClientTLS struct {
	CaCert     url.URL
	ClientCert url.URL
	ClientKey  url.URL
}

type vaultClientJSON struct {
	Vault            string
	AccountDirectory string
	Unlock           []string
	Authorization    vaultClientAuthorizationJSON
	Tls              vaultClientTLSJSON
}

type vaultClientAuthorizationJSON struct {
	Token       string
	RoleId      string
	SecretId    string
	ApprolePath string
}

type vaultClientTLSJSON struct {
	CaCert     string
	ClientCert string
	ClientKey  string
}

func (c *VaultClient) UnmarshalJSON(b []byte) error {
	j := new(vaultClientJSON)
	if err := json.Unmarshal(b, j); err != nil {
		return err
	}
	vc, err := j.vaultClient()
	if err != nil {
		return err
	}
	*c = vc
	return nil
}

func (c vaultClientJSON) vaultClient() (VaultClient, error) {
	vault, err := url.Parse(c.Vault)
	if err != nil {
		return VaultClient{}, err
	}

	accountDirectory, err := url.Parse(c.AccountDirectory)
	if err != nil {
		return VaultClient{}, err
	}

	authorization, err := c.Authorization.vaultClientAuthorization()
	if err != nil {
		return VaultClient{}, err
	}

	tls, err := c.Tls.vaultClientTls()
	if err != nil {
		return VaultClient{}, err
	}

	return VaultClient{
		Vault:            *vault,
		AccountDirectory: *accountDirectory,
		Unlock:           c.Unlock,
		Authorization:    authorization,
		TLS:              tls,
	}, nil
}

func (c vaultClientAuthorizationJSON) vaultClientAuthorization() (vaultClientAuthorization, error) {
	token, err := url.Parse(c.Token)
	if err != nil {
		return vaultClientAuthorization{}, err
	}

	roleId, err := url.Parse(c.RoleId)
	if err != nil {
		return vaultClientAuthorization{}, err
	}

	secretId, err := url.Parse(c.SecretId)
	if err != nil {
		return vaultClientAuthorization{}, err
	}

	return vaultClientAuthorization{
		Token:       environmentVariable(*token),
		RoleId:      environmentVariable(*roleId),
		SecretId:    environmentVariable(*secretId),
		ApprolePath: c.ApprolePath,
	}, nil
}

func (c vaultClientTLSJSON) vaultClientTls() (vaultClientTLS, error) {
	caCert, err := url.Parse(c.CaCert)
	if err != nil {
		return vaultClientTLS{}, err
	}

	clientCert, err := url.Parse(c.ClientCert)
	if err != nil {
		return vaultClientTLS{}, err
	}

	clientKey, err := url.Parse(c.ClientKey)
	if err != nil {
		return vaultClientTLS{}, err
	}

	return vaultClientTLS{
		CaCert:     *caCert,
		ClientCert: *clientCert,
		ClientKey:  *clientKey,
	}, nil
}
