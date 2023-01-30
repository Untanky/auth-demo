package webauthn // TODO: move to different package

import (
	"encoding/json"
	"os"
)

type CorsConfig struct {
	Origin  []string `json:"origins"`
	Headers []string `json:"header"`
}

type Config struct {
	RelyingParty              RelyingParty                    `json:"relyingParty"`
	PublicKeyCredentialParams []*PublicKeyCredentialParameter `json:"publicKeyCredentialParams"`
	Authenticator             string                          `json:"authenticator"`
	Cors                      CorsConfig                      `json:"cors"`
	Port                      int                             `json:"port"`
}

func ReadConfig() (*Config, error) {
	configBytes, _ := os.ReadFile("./config.json")

	config := &Config{}
	json.Unmarshal(configBytes, config)
	return config, nil
}
