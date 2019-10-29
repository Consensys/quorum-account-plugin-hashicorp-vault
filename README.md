# Hashicorp Vault account manager plugin for Quorum
This is to allow Quorum to use accounts stored in Hashicorp Vaults.  New accounts can be created, and existing accounts used for signing.  The implementation is functionally similar to the existing `keystore` account management in `geth` and Quorum and so should be familiar for users of those accounts.

See the [Quorum docs](https://docs.goquorum.com/en/latest/Security/Accounts/Overview/) for more details

## Prerequisites

* Go 1.11.x

## Quick Start
```bash
$ go mod vendor
$ make
$ PLUGIN_DEST_PATH=<path to store plugin distribution zip file> make dist
```

## Example configuration
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
