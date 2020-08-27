package integration

import (
	"os"
)

var distDir = getEnvOrFallback("PLUGIN_DIST", "/Users/chrishounsom/quorum-account-plugin-hashicorp-vault/build/dist")
var distVersion = getEnvOrFallback("PLUGIN_VERSION", "0.2.0-SNAPSHOT")
var vaultPluginDir = getEnvOrFallback("VAULT_PLUGIN_DIR", "/Users/chrishounsom/plugins-for-vault/hashicorp-vault-signing-plugin/build")
var vaultPluginName = getEnvOrFallback("VAULT_PLUGIN_NAME", "quorum-signer-0.0.1-SNAPSHOT")

func getEnvOrFallback(env, fallback string) string {
	if val, ok := os.LookupEnv(env); ok {
		return val
	} else {
		return fallback
	}
}
