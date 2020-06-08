package account

import (
	"net/url"

	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto"
)

type Account struct {
	Address Address
	URL     *url.URL
}

func (a Account) ToProtoAccount() *proto.Account {
	return &proto.Account{
		Address: a.Address.ToBytes(),
		Url:     a.URL.String(),
	}
}
