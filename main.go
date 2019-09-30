package main

import (
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal"
	"github.com/hashicorp/go-plugin"
	"log"
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

func main() {
	log.SetFlags(0) // don't display time
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: DefaultHandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"impl": &internal.SignerPluginImpl{},
		},

		GRPCServer: plugin.DefaultGRPCServer,
	})
}
