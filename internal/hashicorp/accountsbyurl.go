package hashicorp

import (
	"errors"
	"net/url"

	"github.com/consensys/quorum-account-plugin-hashicorp-vault/internal/config"
	util "github.com/consensys/quorum-go-utils/account"
)

type accountsByURL map[*url.URL]config.AccountFile

func (m accountsByURL) HasAccountWithAddress(address util.Address) bool {
	for _, file := range m {
		if file.Contents.Address == address.ToHexString() {
			return true
		}
	}
	return false
}

var (
	unknownAccountErr   = errors.New("unknown account")
	ambiguousAccountErr = errors.New("multiple accounts with same address")
)

func (m accountsByURL) GetAccountWithAddress(address util.Address) (config.AccountFile, error) {
	var (
		isMatched bool
		acct      config.AccountFile
	)

	for _, file := range m {
		if file.Contents.Address == address.ToHexString() {
			if isMatched {
				return config.AccountFile{}, ambiguousAccountErr
			}
			isMatched = true
			acct = file
		}
	}
	if !isMatched {
		return config.AccountFile{}, unknownAccountErr
	}
	return acct, nil
}
