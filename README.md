# Hashicorp Vault plugin for Quorum

The Hashicorp Vault plugin for Quorum enables the storage of Quorum account private keys in a Hashicorp Vault as an alternative to storing as `keystore` files on the node.  It is an implementation of Quorum's [`account` plugin interface](https://docs.goquorum.com/en/latest/PluggableArchitecture/Plugins/account/interface/).

Managing Quorum accounts in a Hashicorp Vault offers several benefits over using the standard `geth` `keystore` files:

* Your account private keys are stored in a Hashicorp Vault which can be deployed on separate infrastructure to your Quorum node  

* Vault enables you to configure permissions on a per-secret basis to ensure account private keys can only be accessed by authorised users/applications 

