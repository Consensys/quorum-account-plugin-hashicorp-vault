package config

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPluginAccountManagerConfig_Validate_NoVaultConfig_Invalid(t *testing.T) {
	c := PluginAccountManagerConfig{}
	err := c.Validate()

	require.Error(t, err)
	require.IsType(t, PluginAccountManagerConfigValidationError{}, err)
	e := err.(PluginAccountManagerConfigValidationError)
	require.Len(t, e.msgs, 1)
	require.ElementsMatch(t, e.msgs, []string{
		noVaultConfigMsg,
	})
}

func TestPluginAccountManagerConfig_Validate_ErrorsConcatenate(t *testing.T) {
	c := PluginAccountManagerConfig{
		Vaults: []VaultConfig{
			{},
		},
	}
	err := c.Validate()

	require.Error(t, err)
	require.IsType(t, PluginAccountManagerConfigValidationError{}, err)
	e := err.(PluginAccountManagerConfigValidationError)
	require.Len(t, e.msgs, 2)
	require.ElementsMatch(t, e.msgs, []string{
		fmt.Sprintf("Vaults[0]: %v", invalidVaultUrlMsg),
		fmt.Sprintf("Vaults[0]: %v", invalidAccountConfigDirMsg),
	})
}

func TestPluginAccountManagerConfig_Validate_MinimumValidConfig(t *testing.T) {
	c := PluginAccountManagerConfig{
		Vaults: []VaultConfig{
			{URL: "url", AccountConfigDir: "dir"},
		},
	}
	err := c.Validate()
	require.NoError(t, err)
}

func TestPluginAccountManagerConfig_Validate_RedefiningAuthIDs(t *testing.T) {
	var err error

	c := PluginAccountManagerConfig{
		Vaults: []VaultConfig{
			{
				URL:              "url",
				AccountConfigDir: "dir",
				Auth: []VaultAuth{
					{AuthID: "A"},
					{AuthID: "B"},
					{AuthID: "C"},
					{AuthID: "A"},
					{AuthID: "B"},
					{AuthID: "B"},
				},
			},
		},
	}
	err = c.Validate()

	require.Error(t, err)
	require.IsType(t, PluginAccountManagerConfigValidationError{}, err)
	e := err.(PluginAccountManagerConfigValidationError)
	require.Len(t, e.msgs, 3)
	require.ElementsMatch(t, e.msgs, []string{
		fmt.Sprintf("Vaults[0]: Auth[3]: %v", invalidAuthIDMsg),
		fmt.Sprintf("Vaults[0]: Auth[4]: %v", invalidAuthIDMsg),
		fmt.Sprintf("Vaults[0]: Auth[5]: %v", invalidAuthIDMsg),
	})
}

func TestPluginAccountManagerConfig_Validate_ErrorsIncludeIndexOfInvalidVaultConfig(t *testing.T) {
	c := PluginAccountManagerConfig{
		Vaults: []VaultConfig{
			{AccountConfigDir: "dir"},
			{URL: "url2"},
		},
	}
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), fmt.Sprintf("Vaults[0]: %v", invalidVaultUrlMsg))
	require.Contains(t, err.Error(), fmt.Sprintf("Vaults[1]: %v", invalidAccountConfigDirMsg))
}
