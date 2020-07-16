# Hashicorp Vault plugin for Quorum

The Hashicorp Vault plugin enables the storage of Quorum account private keys in a [Hashicorp Vault KV v2 secret engine](https://www.vaultproject.io/docs/secrets/kv/kv-v2/).  

Can be used with Quorum or [`clef`](https://docs.goquorum.com/en/latest/Account-Key-Management/Quorum/Clef/). 

## Quickstart 
* [Quickstart](https://docs.goquorum.com/en/latest/Account-Key-Management/Quorum/account-Plugins/Hashicorp-Vault/Quickstart/)

## Building
Quorum will automatically download the plugin from bintray at startup.  

Alternatively, the plugin can be built manually and added to the [`baseDir`](https://docs.goquorum.com/en/latest/PluggableArchitecture/Settings/):
```shell
make
cp build/dist/quorum-account-plugin-hashicorp-vault-<version>.zip /path/to/baseDir
```

## Usage
* [Configuration & additional info](https://docs.goquorum.com/en/latest/Account-Key-Management/Quorum/account-Plugins/Hashicorp-Vault/Overview/)

## Further reading
* [Quorum `account` plugins](https://docs.goquorum.com/en/latest/Account-Key-Management/Quorum/account-Plugins/Overview/)
* [Quorum key management](https://docs.goquorum.com/en/latest/Account-Key-Management/Quorum/Overview)
