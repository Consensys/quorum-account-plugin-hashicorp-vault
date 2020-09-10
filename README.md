# Hashicorp Vault plugin for Quorum

The Hashicorp Vault plugin enables the storage of Quorum account private keys in a [Hashicorp Vault KV v2 secret engine](https://www.vaultproject.io/docs/secrets/kv/kv-v2/).  

Can be used with Quorum or [`clef`](https://docs.goquorum.consensys.net/en/latest/HowTo/ManageKeys/clef/#extending-with-account-plugins). 

Using the Hashicorp Vault plugin offers several benefits:

* Account private keys are stored in a Hashicorp Vault which can be deployed on separate infrastructure to the node  

* Vault allows for fine-grained access control to secrets 

## Building
Quorum will automatically download the plugin from bintray at startup.  

Alternatively, the plugin can be downloaded or built manually and added to the [`baseDir`](https://docs.goquorum.com/en/latest/PluggableArchitecture/Settings/):
```shell
make
cp build/dist/quorum-account-plugin-hashicorp-vault-<version>.zip /path/to/baseDir
```

## Quickstart
See [docs/quickstart-example](docs/quickstart-example.md) for a step-by-step walkthrough of how to set up and use Vault for Quorum account management. 

## Configuration
See [docs/configuration](docs/configuration.md) for complete documentation of the configuration options.

## Creating accounts
See [docs/creating-accounts](docs/creating-accounts.md) for details on creating Vault-stored accounts.

## FAQ
See [docs/faq](docs/faq.md) for additional info on various items. 

## Further reading
* [Quorum `account` plugins](https://docs.goquorum.com/en/latest/Account-Key-Management/Quorum/account-Plugins/Overview/)
* [Quorum key management](https://docs.goquorum.com/en/latest/Account-Key-Management/Quorum/Overview)
