package server

import (
	"github.com/hashicorp/go-plugin"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/hashicorp"
)

type HashicorpPlugin struct {
	plugin.Plugin
	acctManager *hashicorp.AccountManager
}
