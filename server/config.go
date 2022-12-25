package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Untanky/iam-auth/webauthn"
)

type CorsConfig struct {
	Origin  []string `json:"origins"`
	Headers []string `json:"header"`
}

type Config struct {
	RelyingParty              webauthn.RelyingParty                    `json:"relyingParty"`
	PublicKeyCredentialParams []*webauthn.PublicKeyCredentialParameter `json:"publicKeyCredentialParams"`
	Authenticator             string                                   `json:"authenticator"`
	Cors                      CorsConfig                               `json:"cors"`
	Port                      int                                      `json:"port"`
}

func ReadConfig() (*Config, error) {
	configBytes, _ := os.ReadFile("./config.json")

	config := &Config{}
	json.Unmarshal(configBytes, config)
	fmt.Println(config)
	return config, nil
}
