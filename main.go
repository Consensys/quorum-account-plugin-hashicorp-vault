package main

import (
	"log"
	"os"

	"github.com/ConsenSys/quorum-account-plugin-hashicorp-vault/internal/server"
	"github.com/hashicorp/go-plugin"
)

const defaultProtocolVersion = 1

var (
	defaultHandshakeConfig = plugin.HandshakeConfig{
		ProtocolVersion:  defaultProtocolVersion,
		MagicCookieKey:   "QUORUM_PLUGIN_MAGIC_COOKIE",
		MagicCookieValue: "CB9F51969613126D93468868990F77A8470EB9177503C5A38D437FEFF7786E0941152E05C06A9A3313391059132A7F9CED86C0783FE63A8B38F01623C8257664",
	}
)

func main() {
	log.SetFlags(0)          // remove timestamp when logging to host process
	log.SetOutput(os.Stderr) // host process listens to stderr to log
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: defaultHandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"impl": &server.HashicorpPlugin{},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
