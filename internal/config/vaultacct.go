package config

import (
	"fmt"
	"net/url"
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
	SecretName    string
	SecretVersion int64
}

func (c *AccountFileJSON) AccountURL(vaultURL, secretEngineName, apiEndpoint string) (*url.URL, error) {
	u, err := url.Parse(vaultURL)
	if err != nil {
		return nil, err
	}
	acctUrl, err := u.Parse(fmt.Sprintf("v1/%v/%v/%v?version=%v", secretEngineName, apiEndpoint, c.VaultAccount.SecretName, c.VaultAccount.SecretVersion))
	if err != nil {
		return nil, err
	}
	return acctUrl, nil
}

type NewAccount struct {
	SecretName          string
	OverwriteProtection OverwriteProtection
}

type OverwriteProtection struct {
	InsecureDisable bool
	CurrentVersion  uint64
}

func (c *NewAccount) AccountFile(path string, address string, secretVersion int64) AccountFile {
	return AccountFile{
		Path: path,
		Contents: AccountFileJSON{
			Address: address,
			VaultAccount: vaultAccountJSON{
				SecretName:    c.SecretName,
				SecretVersion: secretVersion,
			},
			Version: 1,
		},
	}
}
