package hashicorp

import (
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/types"
	"net/url"

	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
)

type accountsByURL map[*url.URL]config.AccountFile

func (m accountsByURL) HasAccountWithAddress(address types.Address) bool {
	for _, file := range m {
		if file.Contents.Address == address.ToHexString() {
			return true
		}
	}
	return false
}

func (m accountsByURL) GetAccountWithAddress(address types.Address) config.AccountFile {
	for _, file := range m {
		if file.Contents.Address == address.ToHexString() {
			return file
		}
	}
	return config.AccountFile{}
}
