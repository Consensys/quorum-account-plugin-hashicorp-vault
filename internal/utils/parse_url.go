package utils

import (
	"fmt"

	"github.com/ethereum/go-ethereum/accounts"
)

func ToUrl(strUrl string) (accounts.URL, error) {
	if strUrl == "" {
		return accounts.URL{}, nil
	}

	//to parse a string url as an accounts.URL it must first be in json format
	toParse := fmt.Sprintf("\"%v\"", strUrl)

	var url accounts.URL
	if err := url.UnmarshalJSON([]byte(toParse)); err != nil {
		return accounts.URL{}, err
	}

	return url, nil
}
