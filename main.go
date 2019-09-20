package main

import (
	"context"
	"errors"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"log"

	"quorum-plugin-hashicorp-account-store/proto"
)

const DefaultProtocolVersion = 1

var (
	// TODO
	DefaultHandshakeConfig = plugin.HandshakeConfig{
		ProtocolVersion:  DefaultProtocolVersion,
		MagicCookieKey:   "QUORUM_PLUGIN_MAGIC_COOKIE",
		MagicCookieValue: "CB9F51969613126D93468868990F77A8470EB9177503C5A38D437FEFF7786E0941152E05C06A9A3313391059132A7F9CED86C0783FE63A8B38F01623C8257664",
	}
)

type AccountStorePluginImpl struct {
	plugin.Plugin
	status string
}

func (p *AccountStorePluginImpl) Init(ctx context.Context, req *proto.PluginInitialization_Request) (*proto.PluginInitialization_Response, error) {
	p.status = "everything looks ok"
	return &proto.PluginInitialization_Response{}, nil
}

func (p *AccountStorePluginImpl) Status(ctx context.Context, empty *proto.Empty) (*proto.StatusResponse, error) {
	return &proto.StatusResponse{Status: p.status}, nil
}

func (p *AccountStorePluginImpl) GRPCServer(b *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterPluginInitializerServer(s, p)
	proto.RegisterBackendServer(s, p)
	return nil
}

func (p *AccountStorePluginImpl) GRPCClient(ctx context.Context, b *plugin.GRPCBroker, cc *grpc.ClientConn) (interface{}, error) {
	return nil, errors.New("not supported")
}

func main() {
	log.SetFlags(0) // don't display time
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: DefaultHandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"impl": &AccountStorePluginImpl{},
		},

		GRPCServer: plugin.DefaultGRPCServer,
	})
}
