package internal

import (
	"context"
	"errors"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"quorum-plugin-hashicorp-account-store/proto"
)

type SignerPluginImpl struct {
	plugin.Plugin
	initializer
	signer
}

func (p *SignerPluginImpl) GRPCServer(b *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterPluginInitializerServer(s, p)
	proto.RegisterSignerServer(s, p)
	return nil
}

func (p *SignerPluginImpl) GRPCClient(ctx context.Context, b *plugin.GRPCBroker, cc *grpc.ClientConn) (interface{}, error) {
	return nil, errors.New("not supported")
}
