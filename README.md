# Hashicorp Vault account manager plugin for Quorum
This is to provide OAuth2-compliant resource server plugin to Quorum Client. It also implements TLSConfigurationSource service interface to enable TLS for RPC server

## Prerequisites

* Go 1.11.x

## Quick Start
```bash
$ go mod vendor
$ make
$ PLUGIN_DEST_PATH=<path to store plugin distribution zip file> make dist
```

## Configuration

Below is the referenced configuration for the plugin. See the [Quorum docs](https://docs.goquorum.com/en/latest/Security/Accounts/Overview/) for more details

```json
{
    "vaults": [
        {
            "url": "http://localhost:8200",
            "accountConfigDir": "/path/to/acctconfigdir",
            "unlock": "0x4d6d744b6da435b5bbdde2526dc20e9a41cb72e5",
            "auth": [
                {
                    "approlePath": "bar",
                    "authID": "FOO"
                }
            ]
        }
    ]
}    
```
