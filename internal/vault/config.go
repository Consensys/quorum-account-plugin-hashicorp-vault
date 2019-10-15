package vault

import (
	"github.com/ethereum/go-ethereum/accounts"
	"io"
)

type ValidatableAccountParsableConfig interface {
	ValidatableConfig
	AccountParser
}

type ValidatableConfig interface {
	Validate() error
	ValidateForAccountCreation() error
}

type AccountParser interface {
	ParseAccount(vaultAddr, filepath string) (accounts.Account, error)
}

type AccountConfigUnmarshaller interface {
	Unmarshal(r io.Reader) (ValidatableAccountParsableConfig, error)
}
