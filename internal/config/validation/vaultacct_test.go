package validation

import (
	"testing"

	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
	"github.com/stretchr/testify/require"
)

func minimumValidNewAccountConfig() config.NewAccount {
	return config.NewAccount{
		SecretName: "secret",
		OverwriteProtection: config.OverwriteProtection{
			InsecureDisable: false,
			CurrentVersion:  0,
		},
	}
}

func TestNewAccount_Validate_MinimumValidConfig(t *testing.T) {
	err := minimumValidNewAccountConfig().Validate()
	require.NoError(t, err)
}

func TestNewAccount_Validate_SecretName_Invalid(t *testing.T) {
	var (
		conf    config.NewAccount
		err     error
		wantErr = config.InvalidSecretName
	)

	conf = minimumValidNewAccountConfig()
	conf.SecretName = ""
	err = conf.Validate()
	require.EqualError(t, err, wantErr)
}

func TestNewAccount_Validate_OverwriteProtection_Valid(t *testing.T) {
	var (
		conf config.NewAccount
		err  error
	)

	conf = minimumValidNewAccountConfig()
	conf.OverwriteProtection.InsecureDisable = true
	conf.OverwriteProtection.CurrentVersion = 0
	err = conf.Validate()
	require.NoError(t, err)

	conf = minimumValidNewAccountConfig()
	conf.OverwriteProtection.InsecureDisable = false
	conf.OverwriteProtection.CurrentVersion = 1
	err = conf.Validate()
	require.NoError(t, err)

	conf = minimumValidNewAccountConfig()
	conf.OverwriteProtection.InsecureDisable = false
	conf.OverwriteProtection.CurrentVersion = 0
	err = conf.Validate()
	require.NoError(t, err)
}

func TestNewAccount_Validate_OverwriteProtection_Invalid(t *testing.T) {
	var (
		conf    config.NewAccount
		err     error
		wantErr = config.InvalidOverwriteProtection
	)

	conf = minimumValidNewAccountConfig()
	conf.OverwriteProtection.InsecureDisable = true
	conf.OverwriteProtection.CurrentVersion = 1
	err = conf.Validate()
	require.EqualError(t, err, wantErr)
}
