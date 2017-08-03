package vault

import (
	"fmt"

	"github.com/hashicorp/vault/api"
)

// Handle all communication with Vault server
type clientWrapper struct {
	client *api.Client
}

// Initialize a client for Vault.
// It will check the connection information, also execute login if needed.
func newClientWrapper(config *VaultEnvelopeConfig) (*clientWrapper, error) {
	// Check the authentication parameters in config
	err := checkAuthConfig(config)
	if err != nil {
		return nil, err
	}

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

	return &clientWrapper{client}, nil
}

func checkAuthConfig(config *VaultEnvelopeConfig) error {
	var count uint

	if config.Token != "" {
		count++
	}

	if config.ClientCert != "" || config.ClientKey != "" {
		if config.ClientCert == "" || config.ClientKey == "" {
			return fmt.Errorf("vault provider has invalid TLS authentication information")
		}
		count++
	}

	if config.RoleId != "" || config.SecretId != "" {
		if config.RoleId == "" {
			return fmt.Errorf("vault provider has invalid approle authentication information")
		}
		count++
	}

	if count == 0 {
		return fmt.Errorf("vault provider has no authentication information")
	}
	if count > 1 {
		return fmt.Errorf("vault provider has more than one authentication information")
	}

	return nil
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
	resp, err := c.client.Logical().Write("transit/decrypt/"+keyName, data)
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
	resp, err := c.client.Logical().Write("transit/encrypt/"+keyName, data)
	if err != nil {
		return result, err
	}

	result, ok := resp.Data["ciphertext"].(string)
	if !ok {
		return result, fmt.Errorf("failed type assertion of vault encrypt response to string")
	}

	return result, nil
}
