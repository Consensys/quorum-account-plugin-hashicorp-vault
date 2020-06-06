package test

import "os"

const (
	MY_TOKEN     = "MY_TOKEN"
	MY_ROLE_ID   = "MY_ROLE_ID"
	MY_SECRET_ID = "MY_SECRET_ID"
)

func SetToken() {
	os.Setenv(MY_TOKEN, "tokenval")
}

func SetRoleID() {
	os.Setenv(MY_ROLE_ID, "roleidval")
}

func SetSecretID() {
	os.Setenv(MY_SECRET_ID, "secretidval")
}

func UnsetAll() {
	os.Unsetenv(MY_TOKEN)
	os.Unsetenv(MY_ROLE_ID)
	os.Unsetenv(MY_SECRET_ID)
}
