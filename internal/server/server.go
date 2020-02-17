package server

import (
	"github.com/hashicorp/go-plugin"
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto"
)

type HashicorpPlugin struct {
	plugin.Plugin
	acctManager proto.AccountManagerServer
}
