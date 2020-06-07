package types

import (
	"net/url"

	"github.com/ethereum/go-ethereum/common"
)

type Account struct {
	Address common.Address
	URL     *url.URL
}
