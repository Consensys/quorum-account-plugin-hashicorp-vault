package integration

import "encoding/json"

func jsonUnmarshal(s string) (interface{}, error) {
	var j interface{}
	err := json.Unmarshal([]byte(s), &j)
	if err != nil {
		return nil, err
	}
	return j, nil
}

type PersonalListWalletsResp []Wallet

type Wallet struct {
	Accounts []Account
	Status   string
	URL      string
}

type Account struct {
	Address string
	URL     string
}
