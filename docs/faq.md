# FAQ

## What data is stored in Vault?
The string hex representations of the account address and private key, e.g.:

```shell
$ vault kv get kv/myacct
====== Metadata ======
Key              Value
---              -----
created_time     2020-06-29T13:23:00.234716Z
deletion_time    n/a
destroyed        false
version          4

====================== Data ======================
Key                                         Value
---                                         -----
bcc328f4679fcc781d983da1c8be3d3baa6e5ae5    dfe8b73d2771380d3f36bd78ce537715e812d7797c0b055fe944cd42cc750853
```

## What are locked/unlocked accounts?
Accounts can be:

* locked: The plugin does not have the private key (it exists only in Vault)
* unlocked: The plugin has the private key

As with keystore accounts, accounts must be unlocked to sign data.  Accounts can be unlocked by:

* *Recommended*: Using geth's [`personal` API](https://geth.ethereum.org/docs/rpc/ns-personal)
* Setting `unlock` in the [config](configuration.md)

The `personal` API minimises the time an account is unlocked.  The `unlock` config is useful if you need to unlock accounts in bulk for an indefinite amount of time (e.g. testing / Vault requests are impacting performance).

Any unlocked account can be locked with `personal_lockAccount`. 

The `personal_listWallets` API shows account status:
```js
> personal.listWallets
[{
    accounts: [{
        address: "0xda71f07446ed1eca304485dd00c4827ed0984998",
        url: "https://localhost:8200/v1/kv/data/myacct?version=1"
    }, {
        address: "0x0c069eb20e97f18e89e2151d312e9810e80fe089",
        url: "https://localhost:8200/v1/kv/data/myacct?version=2"
    }],
    status: "1 unlocked account(s): [0xda71f07446ed1eca304485dd00c4827ed0984998]",
    url: "plugin://account-plugin-hashicorp-vault"
}]
```

## Removing accounts/moving between nodes 

The files in the `accountDirectory` can be moved as required.  Afterwards, reload the plugin to apply any changes:

```shell tab="HTTP API"
curl -X POST http://localhost:<quorum-rpc-port> \
     -H "Content-type: application/json" \
     --data '{"jsonrpc":"2.0","method":"admin_reloadPlugin","params":["account"],"id":1}'
``` 

```js tab="js console"
admin.reloadPlugin("account")
```

> If the account defined by the file is not available in the target node's Vault then use the `account` plugin [RPC API](https://docs.goquorum.consensys.net/en/latest/HowTo/ManageKeys/AccountPlugins/#rpc-api) or [CLI](https://docs.goquorum.consensys.net/en/latest/HowTo/ManageKeys/AccountPlugins/#cli) to import the account.  This will create the necessary file in the target node's account directory.  

## What password do I use for the personal API?
The `personal` APIs take a `passphrase` argument.  The Hashicorp Vault plugin does not use passwords as the Vault handles encryption of the account data.  

The plugin does not use the `passphrase` so any value can be used, e.g.:

```js
> personal.listWallets
[{
    accounts: [{
        address: "0xda71f07446ed1eca304485dd00c4827ed0984998",
        url: "https://localhost:8200/v1/kv/data/myacct?version=1"
    }],
    status: "0 unlocked account(s): []",
    url: "plugin://account-plugin-hashicorp-vault"
}]

// any value password can be used 
> personal.sign("0xaaaaaa", "0xda71f07446ed1eca304485dd00c4827ed0984998", "")
"0xc432436161788558a1e6387f83b703fecb90cf0507b39afdcd0d54769adc6fe71976bfac421076d54e31d3f45ddf76dcb47ad1a7035a3495d0b40bacfc258df41b"
> personal.sign("0xaaaaaa", "0xda71f07446ed1eca304485dd00c4827ed0984998", "pwd")
"0xc432436161788558a1e6387f83b703fecb90cf0507b39afdcd0d54769adc6fe71976bfac421076d54e31d3f45ddf76dcb47ad1a7035a3495d0b40bacfc258df41b"
``` 

## Approle token renewal
The plugin will automatically renew approle tokens where possible.  If the token is no longer renewable (e.g. because the max TTL has been reached) then the plugin will attempt to reauthenticate and retrieve a new token.  If the token obtained from an approle login is not renewable, then the plugin will not attempt renewal.

For more information about Hashicorp Vault TTL, leases and renewal see the [Vault documentation](https://www.vaultproject.io/docs/concepts/lease.html). 

## Approle policy requirements
To carry out all possible interactions with a Vault, a role must have the following policy capabilities: `["create", "update", "read"]`.  A subset of these capabilities can be configured if not all functionality is required.