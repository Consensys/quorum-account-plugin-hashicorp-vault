package test

import (
	"context"
	"github.com/hashicorp/go-plugin"
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto_common"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/server"
	"google.golang.org/grpc"
)

// testableHashicorpPlugin embeds a server.HashicorpPlugin, overriding the unimplemented GRPCClient(...).  This is so that
// integration tests can create both a plugin server and client to mimic the behaviour of Quorum calling the plugin server.
type testableHashicorpPlugin struct {
	server.HashicorpPlugin
}

type hashicorpPluginGRPCClient struct {
	proto_common.PluginInitializerClient
	proto.AccountManagerClient
}

func (testableHashicorpPlugin) GRPCClient(ctx context.Context, b *plugin.GRPCBroker, cc *grpc.ClientConn) (interface{}, error) {
	return hashicorpPluginGRPCClient{
		PluginInitializerClient: proto_common.NewPluginInitializerClient(cc),
		AccountManagerClient:    proto.NewAccountManagerClient(cc),
	}, nil
}
