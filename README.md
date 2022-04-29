# Hashicorp Vault plugin for Quorum

The Hashicorp Vault plugin enables the storage of Quorum account private keys in a [Hashicorp Vault](https://www.vaultproject.io).  

It can be used with Quorum or [`clef`](https://docs.goquorum.consensys.net/en/latest/HowTo/ManageKeys/clef/#extending-with-account-plugins). 

Using the Hashicorp Vault plugin offers several benefits:

* Account private keys are stored in a Hashicorp Vault which can be deployed on separate infrastructure to the node  

* Vault allows for fine-grained access control to secrets 

## Storage options

Accounts can be stored in the standard [Hashicorp Vault KV v2 secret engine](https://www.vaultproject.io/docs/secrets/kv/kv-v2/) or the custom [`quorum-signer`](https://github.com/consensys/quorum-signer-plugin-for-hashicorp-vault) secret engine:

* **kv**  
    * Account private keys are stored in Vault but must be retrieved by Quorum when signing data
  
* **quorum-signer** *(v0.2.0+ only)*  
    * Account private keys never leave the Vault boundary.  Data is sent to the `quorum-signer` for signing.

## Building
Quorum will automatically download the plugin from bintray at startup.  

Alternatively, the plugin can be downloaded or built manually and added to the [`baseDir`](https://docs.goquorum.consensys.net/en/latest/HowTo/Configure/Plugins/):
```shell
make
cp build/dist/quorum-account-plugin-hashicorp-vault-<version>.zip /path/to/baseDir
```

## Quickstart
See the quickstart examples for step-by-step walkthroughs of how to set up and manage Quorum accounts with Vault:

* Storing accounts in a `kv` secret engine: [docs/quickstart-example-kv](docs/quickstart-example-kv.md)
* Storing accounts in a `quorum-signer` secret engine: [docs/quickstart-example-quorum-signer](docs/quickstart-example-quorum-signer.md)

## Configuration
See [docs/configuration](docs/configuration.md) for complete documentation of the configuration options.

## Creating accounts
See [docs/creating-accounts](docs/creating-accounts.md) for details on creating Vault-stored accounts.

## FAQ
See [docs/faq](docs/faq.md) for additional info on various items. 

## Run tests
```shell
make test

# run integration tests (vault, quorum and clef must be on PATH)
make itest
```

## Further reading
* [Quorum key management](https://docs.goquorum.consensys.net/en/latest/HowTo/ManageKeys/ManagingKeys/)
