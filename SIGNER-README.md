# Using with Quorum Signer plugin for Hashicorp Vault

The Hashicorp Vault plugin for Quorum can be used in conjunction with the [Quorum Signer plugin for Hashicorp Vault](https://github.com/consensys/quorum-signer-plugin-for-hashicorp-vault) to provide additional security for Quorum account private keys.  

This combination ensures Quorum never has to handle account private keys directly; keys are managed by Vault, and never leave the Vault layer.

## Usage

1. [Set-up and enable a `quorum-signer` secret-engine](https://github.com/consensys/quorum-signer-plugin-for-hashicorp-vault) on the Vault server 

1. Use `quorumSignerEngineName` instead of `kvEngineName` in the Hashicorp Vault plugin for Quorum's `config.json`, e.g.:

    ```json
    {
        "vault": "http://localhost:8200",
        "quorumSignerEngineName": "quorum-signer",
        "accountDirectory": "file:///Users/chrishounsom/Desktop/plugins-basedir/hashicorp-acct-store/signer-accts",
        "authentication": {
            "token": "env://HASHICORP_TOKEN"
        }
    }
    ```

## To note

1. The concept of unlocking accounts is not relevant when using `quorum-signer` secret-engines, as account private keys never leave the Vault layer.   

    Therefore, when using `quorum-signer` secret-engines:
    * The `unlock` field in `config.json` is not supported 
    * `personal` account APIs are not supported
    
1. Automatic versioning of secrets in Vault (such as what k/v v2 provides) is not supported by `quorum-signer` secret-engines.  

    Therefore, when using `quorum-signer` secret-engines:
    * Attempting to create a new account with the same `secretName` as an existing account will result in an error.  This prevents accidentally overwriting existing accounts.
    * The `overwriteProtection` section of `config.json` is not required  
