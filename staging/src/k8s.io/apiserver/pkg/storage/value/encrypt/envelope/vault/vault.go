package vault

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	yaml "github.com/ghodss/yaml"

	"k8s.io/apiserver/pkg/storage/value/encrypt/envelope"
)

func VaultKMSFactory(configFile io.Reader) (envelope.Service, error) {
	configFileContents, err := ioutil.ReadAll(configFile)
	if err != nil {
		return nil, fmt.Errorf("could not read contents: %v", err)
	}

	var config VaultEnvelopeConfig
	err = yaml.Unmarshal(configFileContents, &config)
	if err != nil {
		return nil, fmt.Errorf("error while parsing file: %v", err)
	}

	if len(config.KeyNames) == 0 {
		return nil, fmt.Errorf("vault provider has no valid key names")
	}

	client, err := newClientWrapper(&config)
	if err != nil {
		return nil, err
	}

	return &vaultEnvelopeService{keyNames: config.KeyNames, client: client}, nil
}

// VaultConfig contains connection information for Vault transformer
type VaultEnvelopeConfig struct {
	// The names of encryption key for Vault transit communication
	KeyNames []string `json:"key-names"`
	// Vault listen address, for example https://localhost:8200
	Address string `json:"addr"`

	// Token authentication information
	Token string `json:"token"`

	// TLS certificate authentication information
	ClientCert string `json:"client-cert"`
	ClientKey  string `json:"client-key"`

	// AppRole authentication information
	RoleId   string `json:"role-id"`
	SecretId string `json:"secret-id"`

	// CACert is the path to a PEM-encoded CA cert file to use to verify the
	// Vault server SSL certificate.
	CACert string `json:"ca-cert"`

	// TLSServerName, if set, is used to set the SNI host when connecting via TLS.
	TLSServerName string `json:"tls-server-name"`
}

type vaultEnvelopeService struct {
	keyNames []string
	client   *clientWrapper
}

func (s *vaultEnvelopeService) Decrypt(data string) ([]byte, error) {
	// Find the mached key
	var key string
	for _, name := range s.keyNames {
		if strings.HasPrefix(data, name+":") {
			key = name
			break
		}
	}
	if key == "" {
		return nil, fmt.Errorf("no matching vault key found")
	}

	// Replace the key name with "vault:" for Vault transit API
	cipher := strings.Replace(data, key, "vault", 1)

	plain, err := s.client.decrypt(key, cipher)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(plain)
}

func (s *vaultEnvelopeService) Encrypt(data []byte) (string, error) {
	// Use the frist key to encrypt
	key := s.keyNames[0]
	plain := base64.StdEncoding.EncodeToString(data)

	cipher, err := s.client.encrypt(key, plain)
	if err != nil {
		return "", err
	}

	// The format of cipher from Vault is "vault:v1:....".
	// "vault:" is unnecessary for this transformer, remove it.
	return strings.Replace(cipher, "vault", key, 1), nil
}
