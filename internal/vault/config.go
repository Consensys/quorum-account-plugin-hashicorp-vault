package vault

import (
	"github.com/ethereum/go-ethereum/accounts"
	"io"
)

type ValidatableAccountGetterConfig interface {
	ValidatableConfig
	AccountGetter
}

type ValidatableConfig interface {
	Validate() error
	ValidateForAccountCreation() error
}

type AccountGetter interface {
	AsAccount(urlPath string) *accounts.Account
}

type AccountConfigUnmarshaller interface {
	Unmarshal(r io.Reader) (ValidatableAccountGetterConfig, error)
}
