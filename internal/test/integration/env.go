package integration

import (
	"os"
)

var distDir = getEnvOrFallback("PLUGIN_DIST", "../quorum-account-plugin-hashicorp-vault/build/dist")
var distVersion = getEnvOrFallback("PLUGIN_VERSION", "0.2.2-SNAPSHOT")
var vaultPluginDir = getEnvOrFallback("VAULT_SIGNER_DIR", "../quorum-signer-plugin-for-hashicorp-vault/build")
var vaultPluginName = getEnvOrFallback("VAULT_SIGNER_NAME", "quorum-signer-0.2.2-SNAPSHOT")

func getEnvOrFallback(env, fallback string) string {
	if val, ok := os.LookupEnv(env); ok {
		return val
	} else {
		return fallback
	}
}
