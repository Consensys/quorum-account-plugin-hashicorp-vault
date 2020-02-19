package config

import (
	"encoding/json"
	"net/url"
)

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
