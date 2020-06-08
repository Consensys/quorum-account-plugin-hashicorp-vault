package hashicorp

import (
	"net/url"

	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/account"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
)

type accountsByURL map[*url.URL]config.AccountFile

func (m accountsByURL) HasAccountWithAddress(address account.Address) bool {
	for _, file := range m {
		if file.Contents.Address == address.ToHexString() {
			return true
		}
	}
	return false
}

func (m accountsByURL) GetAccountWithAddress(address account.Address) config.AccountFile {
	for _, file := range m {
		if file.Contents.Address == address.ToHexString() {
			return file
		}
	}
	return config.AccountFile{}
}
