package hashicorp

import (
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
)

type accountsByURL map[accounts.URL]config.AccountFile

func (m accountsByURL) HasAccountWithAddress(address common.Address) bool {
	for _, file := range m {
		if file.Contents.Address == common.Bytes2Hex(address.Bytes()) {
			return true
		}
	}
	return false
}

func (m accountsByURL) GetAccountWithAddress(address common.Address) config.AccountFile {
	for _, file := range m {
		if file.Contents.Address == common.Bytes2Hex(address.Bytes()) {
			return file
		}
	}
	return config.AccountFile{}
}
