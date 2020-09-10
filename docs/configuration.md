# Configuration

Add the following `providers` config to the [`--plugins` file](../../../../../PluggableArchitecture/Settings):
```json
{
    "providers": {
        "account": {
            "name": "quorum-account-plugin-hashicorp-vault",
            "version": "0.0.1",
            "config": "<config>"
        }
    }
}
```

Based on this config, Quorum will look for [`quorum-account-plugin-hashicorp-vault-0.0.1.zip` in the default `baseDir`](../../../../../PluggableArchitecture/Internals#discovery).

`<config>` is the Hashicorp Vault plugin configuration:

!!! info   
    This config can be provided in [several ways](../../../../../PluggableArchitecture/Settings#plugindefinition)

```json
{
    "vault": "https://localhost:8200",
    "kvEngineName": "my-kv-engine",
    "accountDirectory": "file:///path/to/accts",
    "unlock": ["1a31744b4a6ee9f3c3d1550beb56d53d2a4fa454"],
    "authentication": {
        "roleId": "env://HASHICORP_ROLE_ID",
        "secretId": "env://HASHICORP_SECRET_ID",
        "approlePath": "approle"
    },
    "tls": {
        "caCert": "file:///path/to/ca.pem",
        "clientCert": "file:///path/to/client.pem",
        "clientKey": "file:///path/to/client.key"
    }
}
```

| Field | Description |
| --- | --- |
| `vault` | Vault server URL |
| `kvEngineName` | Name of an enabled Vault KV v2 secret engine to use for account storage |
| `accountDirectory` | Absolute `file://` URL of the account directory.  See [accountDirectory](#accountdirectory) |
| `unlock` | (Optional) List of accounts to retrieve from Vault at startup and store in memory |
| `authentication` | See [authentication](#authentication) |
| `tls` | (Optional) See [tls](#tls) |

### accountDirectory
The `accountDirectory` contains config files for each account managed by the plugin.  These files are similar to [keystore files](../../../Keystore-Files), except they do not contain any private data.

Typically these files do not have to be created or edited manually.  See [Creating accounts](#creating-accounts).

#### Example account file contents
```json
{
   "Address" : "1a31744b4a6ee9f3c3d1550beb56d53d2a4fa454",
   "VaultAccount" : {
      "SecretName" : "myacct",
      "SecretVersion" : 4
   },
   "Version" : 1
}
```


### authentication

The plugin can authenticate with Vault using [approle](https://www.vaultproject.io/docs/auth/approle) or [token](https://www.vaultproject.io/docs/auth/token) Vault authentication methods.


#### approle
!!! warning 
    approle is recommended in production
    
| Field | Description |
| --- | --- |
| `roleId` | approle role ID env URL (e.g. `env://VAR` will use the value of the `VAR` env variable) |
| `secretId` | approle secret ID env URL (e.g. `env://VAR` will use the value of the `VAR` env variable) |
| <span style="white-space:nowrap">`approlePath`</span> | name/path of the approle engine to login to |

#### token
| Field | Description |
| --- | --- |
| `token` | Vault token env URL (e.g. `env://VAR` will use the value of the `VAR` env variable) |

### tls

!!! warning 
    TLS is recommended in production

| Field | Description |
| --- | --- |
| `caCert` | Absolute `file://` URL of PEM-encoded CA certificate |
| `clientCert` | Absolute `file://` URL of PEM-encoded client certificate |
| `clientKey` | Absolute `file://` URL of PEM-encoded client key |
