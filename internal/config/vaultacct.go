package config

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/ethereum/go-ethereum/accounts"
)

type AccountFile struct {
	Path     string
	Contents AccountFileJSON
}

type AccountFileJSON struct {
	Address      string
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
