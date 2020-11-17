# Creating accounts

New accounts can be created and stored directly into the Vault by using the `account` plugin [RPC API](https://docs.goquorum.consensys.net/en/latest/HowTo/ManageKeys/AccountPlugins/#rpc-api) or [CLI](https://docs.goquorum.consensys.net/en/latest/HowTo/ManageKeys/AccountPlugins/#cli).  

A json config must be provided to the API/CLI when creating accounts.  Example:

```json
{
    "secretName": "myacct",
    "overwriteProtection": {
      "currentVersion": 4
    }
}
```

| Field | Description |
| --- | --- |
| `secretName` | Secret name/path the plugin will store the new account at |
| <span style="white-space:nowrap">`overwriteProtection.currentVersion`</span><br/>*or*<br/><span style="white-space:nowrap">`overwriteProtection.insecureDisable`</span> | Current integer version of this secret in Vault (`0` if no previous version exists)<br/>*or*<br/>Disable overwrite protection |

## kv secret engine

The plugin creates the account in memory, writes it to Vault, and zeros the private key.  The plugin never writes the private key to the node's disk.

### overwriteProtection

Typical usage will be to create separate Vault secrets for each account.  However, KV v2 secret engines also support secret versioning. 

The plugin uses [KV v2's Check-And-Set (CAS) feature](https://www.vaultproject.io/api-docs/secret/kv/kv-v2#create-update-secret) to protect against accidentally creating a new version of an existing secret.

If a secret with the same name already exists, `currentVersion` must be provided and must equal the current version number of the secret.

The CAS check can be skipped by setting `"insecureDisable": "true"`.  

> **Warning: Prevent accidental loss of account data**
> 
> The K/V Version 2 secret engine supports versioning of secrets, however only a limited number of versions are retained (10 by default).  
>
> This `max-versions` number can be set during creation of the secret engine or changed at a later date by using the Vault [HTTP API](https://www.vaultproject.io/api/secret/kv/kv-v2.html#configure-the-kv-engine) or Vault CLI:
>
> ``` bash
> vault kv metadata put -max-versions <num> <kvEngineName>/<secretName>
> ```

## quorum-signer secret engine

The plugin makes a request to the `quorum-signer` secret-engine to create a new account.  The account private key only exists within the Vault boundary.

### overwriteProtection

The `quorum-signer` secret-engine does not support automatic versioning of secrets.  

Therefore, when using `quorum-signer` secret-engines:

* Attempting to create a new account with the same `secretName` as an existing account will result in an error.  This prevents accidentally overwriting existing accounts.
* The `overwriteProtection` section of the new account config does not need to be defined
