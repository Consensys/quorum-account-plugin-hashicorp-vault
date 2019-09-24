package internal

import (
	"context"
	"quorum-plugin-hashicorp-account-store/proto"
)

type initializer struct{}

func (i *initializer) Init(ctx context.Context, req *proto.PluginInitialization_Request) (*proto.PluginInitialization_Response, error) {
	// read config and start signer

	return &proto.PluginInitialization_Response{}, nil
}
