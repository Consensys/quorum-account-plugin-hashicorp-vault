package utils

import "io/ioutil"

var (
	Acct1JsonConfig = []byte(`{
  "address": "dc99ddec13457de6c0f6bb8e6cf3955c86f55526",
  "vaultsecret": {
    "pathparams": {
      "secretenginepath": "kv",
      "secretpath": "kvacct",
      "secretversion": 1
    },
    "authid": "FOO"
  },
  "id": "afb297d8-1995-4212-974a-e861d7e31e19",
  "version": 1
}`)
	Acct1JsonConfigDiffPathParams = []byte(`{
  "address": "dc99ddec13457de6c0f6bb8e6cf3955c86f55526",
  "vaultsecret": {
    "pathparams": {
      "secretenginepath": "kvalt",
      "secretpath": "kvacctalt",
      "secretversion": 2
    },
    "authid": "FOO"
  },
  "id": "afb297d8-1995-4212-974a-e861d7e31e19",
  "version": 1
}`)
	Acct2JsonConfig = []byte(`{
  "address": "4d6d744b6da435b5bbdde2526dc20e9a41cb72e5",
  "vaultsecret": {
    "pathparams": {
      "secretenginepath": "engine",
      "secretpath": "engineacct",
      "secretversion": 2
    },
    "authid": "FOO"
  },
  "id": "d88bd481-4db4-4ee5-8ea6-84042d2fb0cf",
  "version": 1
}`)
	Acct3JsonConfig = []byte(`{
   "address" : "29b409d5c50d7ed5cdee9679d6baeb1bad640841",
   "vaultsecret" : {
      "authid" : "BAR",
      "pathparams" : {
         "secretenginepath" : "engine",
         "secretpath" : "engineacct",
         "secretversion" : 7
      }
   },
   "id" : "f66f3b2e-bef2-4279-bc7c-259137cc3440",
   "version" : 1
}
`)
	Acct4JsonConfig = []byte(`{
  "address": "1c15560b23dfa9a19e9739cc866c7f1f2e5da7b7",
  "vaultsecret": {
    "pathparams": {
      "secretenginepath": "kv",
      "secretpath": "kvacct",
      "secretversion": 5
    },
    "authid": "BAR"
  },
  "id": "974ceed7-5157-4d33-877b-196047509c4d",
  "version": 1
}
`)
)

func AddTempFile(dir string, content []byte) (string, error) {
	tmpFile, err := ioutil.TempFile(dir, "")
	if err != nil {
		return "", err
	}

	path := tmpFile.Name()

	if _, err := tmpFile.Write(content); err != nil {
		return "", err
	}
	if err := tmpFile.Close(); err != nil {
		return "", err
	}
	return path, nil
}
