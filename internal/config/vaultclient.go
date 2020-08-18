package config

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
)

// vaultClientBase encapsulates common config fields between the kv and quorum-signer vault clients to simplify validation
type vaultClientBase struct {
	Vault            *url.URL
	AccountDirectory *url.URL
	Authentication   VaultClientAuthentication
	TLS              VaultClientTLS
}

type VaultClient struct {
	vaultClientBase
	KVEngineName           string // the path of the K/V v2 secret engine
	QuorumSignerEngineName string // the path of the quorum-signer secret engine
	Unlock                 []string
}

type EnvironmentVariable url.URL

func (e EnvironmentVariable) Get() string {
	u := url.URL(e)
	return os.Getenv(u.Host)
}

func (e EnvironmentVariable) IsSet() bool {
	u := url.URL(e)
	if u.Host == "" {
		return false
	}
	_, b := os.LookupEnv(u.Host)
	return b
}

func (e EnvironmentVariable) String() string {
	u := url.URL(e)
	return u.String()
}

type VaultClientAuthentication struct {
	Token       *EnvironmentVariable
	RoleId      *EnvironmentVariable
	SecretId    *EnvironmentVariable
	ApprolePath string
}

type VaultClientTLS struct {
	CaCert     *url.URL
	ClientCert *url.URL
	ClientKey  *url.URL
}

type vaultClientJSON struct {
	Vault                  string
	KVEngineName           string
	QuorumSignerEngineName string
	AccountDirectory       string
	Unlock                 []string
	Authentication         vaultClientAuthenticationJSON
	Tls                    vaultClientTLSJSON
}

type vaultClientAuthenticationJSON struct {
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

func (c *VaultClient) MarshalJSON() ([]byte, error) {
	j, err := c.vaultClientJSON()
	if err != nil {
		return nil, err
	}
	return json.Marshal(j)
}

func (c vaultClientJSON) vaultClient() (VaultClient, error) {
	vault, err := url.Parse(c.Vault)
	if err != nil {
		return VaultClient{}, err
	}

	if !strings.HasSuffix(c.AccountDirectory, "/") {
		c.AccountDirectory = c.AccountDirectory + "/"
	}
	accountDirectory, err := url.Parse(c.AccountDirectory)
	if err != nil {
		return VaultClient{}, err
	}

	authentication, err := c.Authentication.vaultClientAuthentication()
	if err != nil {
		return VaultClient{}, err
	}

	tls, err := c.Tls.vaultClientTls()
	if err != nil {
		return VaultClient{}, err
	}

	return VaultClient{
		vaultClientBase: vaultClientBase{
			Vault:            vault,
			AccountDirectory: accountDirectory,
			Authentication:   authentication,
			TLS:              tls,
		},
		KVEngineName:           c.KVEngineName,
		QuorumSignerEngineName: c.QuorumSignerEngineName,
		Unlock:                 c.Unlock,
	}, nil
}

func (c vaultClientAuthenticationJSON) vaultClientAuthentication() (VaultClientAuthentication, error) {
	token, err := url.Parse(c.Token)
	if err != nil {
		return VaultClientAuthentication{}, err
	}

	roleId, err := url.Parse(c.RoleId)
	if err != nil {
		return VaultClientAuthentication{}, err
	}

	secretId, err := url.Parse(c.SecretId)
	if err != nil {
		return VaultClientAuthentication{}, err
	}

	var (
		tEnv = EnvironmentVariable(*token)
		rEnv = EnvironmentVariable(*roleId)
		sEnv = EnvironmentVariable(*secretId)
	)

	return VaultClientAuthentication{
		Token:       &tEnv,
		RoleId:      &rEnv,
		SecretId:    &sEnv,
		ApprolePath: c.ApprolePath,
	}, nil
}

func (c vaultClientTLSJSON) vaultClientTls() (VaultClientTLS, error) {
	caCert, err := url.Parse(c.CaCert)
	if err != nil {
		return VaultClientTLS{}, err
	}

	clientCert, err := url.Parse(c.ClientCert)
	if err != nil {
		return VaultClientTLS{}, err
	}

	clientKey, err := url.Parse(c.ClientKey)
	if err != nil {
		return VaultClientTLS{}, err
	}

	return VaultClientTLS{
		CaCert:     caCert,
		ClientCert: clientCert,
		ClientKey:  clientKey,
	}, nil
}

func (c VaultClient) vaultClientJSON() (vaultClientJSON, error) {
	return vaultClientJSON{
		Vault:                  c.Vault.String(),
		KVEngineName:           c.KVEngineName,
		QuorumSignerEngineName: c.QuorumSignerEngineName,
		AccountDirectory:       c.AccountDirectory.String(),
		Unlock:                 c.Unlock,
		Authentication:         c.Authentication.vaultClientAuthenticationJSON(),
		Tls:                    c.TLS.vaultClientTLSJSON(),
	}, nil
}

func (c VaultClientAuthentication) vaultClientAuthenticationJSON() vaultClientAuthenticationJSON {
	return vaultClientAuthenticationJSON{
		Token:       c.Token.String(),
		RoleId:      c.RoleId.String(),
		SecretId:    c.SecretId.String(),
		ApprolePath: c.ApprolePath,
	}
}

func (c VaultClientTLS) vaultClientTLSJSON() vaultClientTLSJSON {
	return vaultClientTLSJSON{
		CaCert:     c.CaCert.String(),
		ClientCert: c.ClientCert.String(),
		ClientKey:  c.ClientKey.String(),
	}
}
