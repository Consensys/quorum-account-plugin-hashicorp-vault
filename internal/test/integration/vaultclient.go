package integration

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type kvSecret struct {
	addr, key string
}

func getKVSecret(t *testing.T, vaultURL, kvName, secretName string, version int, token string) kvSecret {
	httpClient := http.DefaultClient

	url := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", vaultURL, kvName, secretName, version)
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)

	req.Header.Add("X-Vault-Token", token)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	byt, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)

	var result map[string]interface{}

	err = json.Unmarshal(byt, &result)
	require.NoError(t, err)

	secret := result["data"].(map[string]interface{})["data"].(map[string]interface{})
	require.Len(t, secret, 1)

	var (
		addr, key string
	)
	for k, v := range secret {
		addr = k
		key = v.(string)
	}
	return kvSecret{addr: addr, key: key}
}

func getKVSecretExpect404(t *testing.T, vaultURL, kvName, secretName string, version int, token string) {
	httpClient := http.DefaultClient

	url := fmt.Sprintf("%v/v1/%v/data/%v?version=%v", vaultURL, kvName, secretName, version)
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)

	req.Header.Add("X-Vault-Token", token)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 404, resp.StatusCode)
}

func enableSignerPlugin(t *testing.T, vaultURL, token string) {
	httpClient := http.DefaultClient

	url := fmt.Sprintf("%v/v1/sys/mounts/quorum-signer", vaultURL)

	reqBody := fmt.Sprintf(`{
	"type": "%v"
}`, vaultPluginName)

	req, err := http.NewRequest("POST", url, strings.NewReader(reqBody))
	require.NoError(t, err)

	req.Header.Add("X-Vault-Token", token)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)

	require.Equalf(t, 204, resp.StatusCode, "unsuccessful request: code=%v, status=%v, body=%v", resp.StatusCode, resp.Status, string(respBody))
}

type signerSecret struct {
	addr string
}

func getSignerSecret(t *testing.T, vaultURL, signerName, secretName string, token string) signerSecret {
	httpClient := http.DefaultClient

	url := fmt.Sprintf("%v/v1/%v/accounts/%v", vaultURL, signerName, secretName)
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)

	req.Header.Add("X-Vault-Token", token)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	byt, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)

	var result map[string]interface{}

	err = json.Unmarshal(byt, &result)
	require.NoError(t, err)

	secret := result["data"].(map[string]interface{})
	require.Len(t, secret, 1)

	return signerSecret{addr: secret["addr"].(string)}
}

func getSignerSecretExpect404(t *testing.T, vaultURL, signerName, secretName string, token string) {
	httpClient := http.DefaultClient

	url := fmt.Sprintf("%v/v1/%v/accounts/%v", vaultURL, signerName, secretName)
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)

	req.Header.Add("X-Vault-Token", token)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 404, resp.StatusCode)
}
