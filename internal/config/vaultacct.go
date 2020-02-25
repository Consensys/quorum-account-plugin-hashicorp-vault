package config

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"net/url"
)

type AccountFile struct {
	Path     string
	Contents AccountFileJSON
}

type AccountFileJSON struct {
	Address      string // TODO(cjh) use hex encoded bytes instead of string (to account for 0x[...] or just [...])
	VaultAccount vaultAccountJSON
	Version      int
}

type vaultAccountJSON struct {
	SecretEnginePath string
	SecretPath       string
	SecretVersion    int64
}

func (c *AccountFileJSON) AccountURL(vaultURL string) (accounts.URL, error) {
	u, err := url.Parse(vaultURL)
	if err != nil {
		return accounts.URL{}, err
	}
	acctUrl, err := u.Parse(fmt.Sprintf("v1/%v/data/%v?version=%v", c.VaultAccount.SecretEnginePath, c.VaultAccount.SecretPath, c.VaultAccount.SecretVersion))
	if err != nil {
		return accounts.URL{}, err
	}

	jsonUrl := fmt.Sprintf("\"%v\"", acctUrl.String())

	result := new(accounts.URL)
	if err := json.Unmarshal([]byte(jsonUrl), result); err != nil {
		return accounts.URL{}, err
	}

	return *result, nil
}

type NewAccount struct {
	Vault            *url.URL
	SecretEnginePath string
	SecretPath       string
	InsecureSkipCAS  bool
	CASValue         uint64
}

type newAccountJSON struct {
	Vault            string
	SecretEnginePath string
	SecretPath       string
	InsecureSkipCAS  bool
	CASValue         uint64
}

func (c *NewAccount) AccountFile(path string, address string, secretVersion int64) AccountFile {
	return AccountFile{
		Path: path,
		Contents: AccountFileJSON{
			Address: address,
			VaultAccount: vaultAccountJSON{
				SecretEnginePath: c.SecretEnginePath,
				SecretPath:       c.SecretPath,
				SecretVersion:    secretVersion,
			},
			Version: 1,
		},
	}
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
		Vault:            vault,
		SecretEnginePath: c.SecretEnginePath,
		SecretPath:       c.SecretPath,
		InsecureSkipCAS:  c.InsecureSkipCAS,
		CASValue:         c.CASValue,
	}, nil
}
