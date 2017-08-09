package vault

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
)

// Handle all communication with Vault server
type clientWrapper struct {
	client      *api.Client
	encryptPath string
	decryptPath string
}

// Initialize a client for Vault.
func newClientWrapper(config *VaultEnvelopeConfig) (*clientWrapper, error) {
	client, err := newApiClient(config)
	if err != nil {
		return nil, err
	}

	// Set token for the client
	switch {
	case config.Token != "":
		client.SetToken(config.Token)
	case config.ClientCert != "" && config.ClientKey != "":
		err = loginByTls(config, client)
	case config.RoleId != "":
		err = loginByAppRole(config, client)
	}
	if err != nil {
		return nil, err
	}

	// Vault transit path is configurable.
	// "path", "/path", "path/" and "/path/" are the same.
	transit := "transit"
	if config.TransitPath != "" {
		transit = strings.Trim(config.TransitPath, "/")
	}

	wrapper := clientWrapper{
		client:      client,
		encryptPath: transit + "/encrypt/",
		decryptPath: transit + "/decrypt/",
	}
	return &wrapper, nil
}

func newApiClient(config *VaultEnvelopeConfig) (*api.Client, error) {
	apiConfig := api.DefaultConfig()

	apiConfig.Address = config.Address

	tlsConfig := &api.TLSConfig{
		CACert:        config.CACert,
		ClientCert:    config.ClientCert,
		ClientKey:     config.ClientKey,
		TLSServerName: config.TLSServerName,
	}
	err := apiConfig.ConfigureTLS(tlsConfig)
	if err != nil {
		return nil, err
	}

	return api.NewClient(apiConfig)
}

func loginByTls(config *VaultEnvelopeConfig, client *api.Client) error {
	resp, err := client.Logical().Write("/auth/cert/login", nil)
	if err != nil {
		return err
	}

	client.SetToken(resp.Auth.ClientToken)
	return nil
}

func loginByAppRole(config *VaultEnvelopeConfig, client *api.Client) error {
	data := map[string]interface{}{
		"role_id":   config.RoleId,
		"secret_id": config.SecretId,
	}
	resp, err := client.Logical().Write("/auth/approle/login", data)
	if err != nil {
		return err
	}

	client.SetToken(resp.Auth.ClientToken)
	return nil
}

func (c *clientWrapper) decrypt(keyName string, cipher string) (string, error) {
	var result string

	data := map[string]interface{}{
		"ciphertext": cipher,
	}
	resp, err := c.client.Logical().Write(c.decryptPath+keyName, data)
	if err != nil {
		return result, err
	}

	result, ok := resp.Data["plaintext"].(string)
	if !ok {
		return result, fmt.Errorf("failed type assertion of vault decrypt response to string")
	}

	return result, nil
}

func (c *clientWrapper) encrypt(keyName string, plain string) (string, error) {
	var result string

	data := map[string]interface{}{
		"plaintext": plain,
	}
	resp, err := c.client.Logical().Write(c.encryptPath+keyName, data)
	if err != nil {
		return result, err
	}

	result, ok := resp.Data["ciphertext"].(string)
	if !ok {
		return result, fmt.Errorf("failed type assertion of vault encrypt response to string")
	}

	return result, nil
}
