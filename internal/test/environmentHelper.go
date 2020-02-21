package test

import "os"

const (
	MY_TOKEN     = "MY_TOKEN"
	MY_ROLE_ID   = "MY_ROLE_ID"
	MY_SECRET_ID = "MY_SECRET_ID"
)

type EnvironmentHelper struct{}

func (EnvironmentHelper) SetToken() {
	os.Setenv(MY_TOKEN, "tokenval")
}

func (EnvironmentHelper) SetRoleID() {
	os.Setenv(MY_ROLE_ID, "roleidval")
}

func (EnvironmentHelper) SetSecretID() {
	os.Setenv(MY_SECRET_ID, "secretidval")
}

func (EnvironmentHelper) UnsetAll() {
	os.Unsetenv(MY_TOKEN)
	os.Unsetenv(MY_ROLE_ID)
	os.Unsetenv(MY_SECRET_ID)
}
