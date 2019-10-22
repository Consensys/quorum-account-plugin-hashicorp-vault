package config

import (
	"github.com/ethereum/go-ethereum/accounts"
)

const (
	WalletScheme = "hashiwlt"
	AcctScheme   = "hashiacct"
)

type AccountAndWalletUrl struct {
	Account   accounts.Account
	WalletUrl accounts.URL
}
