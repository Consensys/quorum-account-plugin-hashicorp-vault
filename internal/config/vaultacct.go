package config

import (
	"encoding/json"
	"fmt"
	"net/url"
)

type AccountFile struct {
	Path     string
	Contents AccountFileJSON
}

type AccountFileJSON struct {
	Address      string // TODO(cjh) use hex encoded bytes instead of string (to account for 0x[...] or just [...])
	VaultAccount vaultAccountJSON
	ID           string
	Version      int
}

type vaultAccountJSON struct {
	SecretEnginePath string
	SecretPath       string
	SecretVersion    int64
}

func (c *AccountFileJSON) AccountURL(vaultURL string) (*url.URL, error) {
	u, err := url.Parse(vaultURL)
	if err != nil {
		return nil, err
	}
	result, err := u.Parse(fmt.Sprintf("%v/%v?version=%v", c.VaultAccount.SecretEnginePath, c.VaultAccount.SecretPath, c.VaultAccount.SecretVersion))
	if err != nil {
		return nil, err
	}
	return result, nil
}

type NewAccount struct {
	Vault            url.URL
	SecretEnginePath string
	SecretPath       string
	SecretVersion    int64
	InsecureSkipCAS  bool
	CASValue         uint64
}

type newAccountJSON struct {
	Vault            string
	SecretEnginePath string
	SecretPath       string
	SecretVersion    int64
	InsecureSkipCAS  bool
	CASValue         uint64
}

func (c *NewAccount) UnmarshalJSON(b []byte) error {
	j := new(newAccountJSON)
	if err := json.Unmarshal(b, j); err != nil {
		return err
	}
	na, err := j.newAccount()
	if err != nil {
		return err
	}
	*c = na
	return nil
}

func (c newAccountJSON) newAccount() (NewAccount, error) {
	vault, err := url.Parse(c.Vault)
	if err != nil {
		return NewAccount{}, err
	}

	return NewAccount{
		Vault:            *vault,
		SecretEnginePath: c.SecretEnginePath,
		SecretPath:       c.SecretPath,
		SecretVersion:    c.SecretVersion,
		InsecureSkipCAS:  c.InsecureSkipCAS,
		CASValue:         c.CASValue,
	}, nil
}
