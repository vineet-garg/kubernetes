package vault

import (
	"bytes"
	"strings"
	"testing"

	"k8s.io/apiserver/pkg/storage/value/encrypt/envelope"
)

const (
	sampleText = "abcdefghijklmnopqrstuvwxyz"

	configOneKey = `
key-names: 
  - @key@
addr: @url@
ca-cert: testdata/ca.crt
token: 8dad1053-4a4e-f359-2eab-d57968eb277f
`
	configTwoKey = `
key-names: 
  - @key@
  - @key@
addr: @url@
ca-cert: testdata/ca.crt
token: 8dad1053-4a4e-f359-2eab-d57968eb277f
`
	configNoKey = `
addr: @url@
ca-cert: testdata/ca.crt
token: 8dad1053-4a4e-f359-2eab-d57968eb277f
`
)

func TestOneKey(t *testing.T) {
	server := VaultTestServer(t)
	defer server.Close()

	key := "kube-secret-enc-key"
	service, err := serviceTestFactory(configOneKey, server.URL, key)
	if err != nil {
		t.Fatal("fail to initialize Vault envelope service", err)
	}

	originalText := []byte(sampleText)

	cipher, err := service.Encrypt(originalText)
	if err != nil {
		t.Fatal("fail to encrypt data with Vault", err)
	}
	if !strings.HasPrefix(cipher, key+":v1:") {
		t.Errorf("the cipher has no correct prefix, %s", cipher)
	}

	untransformedData, err := service.Decrypt(cipher)
	if err != nil {
		t.Fatal("fail to decrypt data with Vault", err)
	}
	if bytes.Compare(untransformedData, originalText) != 0 {
		t.Fatalf("transformed data incorrectly. Expected: %v, got %v", originalText, untransformedData)
	}
}

func TestMoreThanOneKeys(t *testing.T) {
	server := VaultTestServer(t)
	defer server.Close()

	// Create cipher when there is one key
	key := "kube-secret-enc-key"
	service, err := serviceTestFactory(configOneKey, server.URL, key)
	if err != nil {
		t.Fatal("fail to initialize Vault envelope service", err)
	}

	originalText := []byte(sampleText)

	cipher, err := service.Encrypt(originalText)
	if err != nil {
		t.Fatal("fail to encrypt data with Vault", err)
	}

	// Now there are 2 keys in the service
	newKey := "new-" + key

	newService, err := serviceTestFactory(configTwoKey, server.URL, newKey, key)
	if err != nil {
		t.Fatal("fail to initialize Vault envelope service", err)
	}

	newCipher, err := newService.Encrypt(originalText)
	if err != nil {
		t.Fatal("fail to encrypt data with Vault", err)
	}
	// New cipher should be prefixed with new key
	if !strings.HasPrefix(newCipher, newKey+":v1:") {
		t.Errorf("the cipher has no correct prefix, %s", cipher)
	}

	// Both old cipher and new cipher should be decrypted correctly
	for _, cipherData := range []string{cipher, newCipher} {
		untransformedData, err := newService.Decrypt(cipherData)
		if err != nil {
			t.Fatal("fail to decrypt data with Vault", err)
		}
		if bytes.Compare(untransformedData, originalText) != 0 {
			t.Fatalf("transformed data incorrectly. Expected: %v, got %v", originalText, untransformedData)
		}
	}
}

func TestNoKey(t *testing.T) {
	server := VaultTestServer(t)
	defer server.Close()

	_, err := serviceTestFactory(configNoKey, server.URL)
	if err == nil {
		t.Fatal("should fail to create vault KMS service when there is no key name in configure")
	}
}

func TestWithoutMatchKey(t *testing.T) {
	server := VaultTestServer(t)
	defer server.Close()

	key := "kube-secret-enc-key"
	service, err := serviceTestFactory(configOneKey, server.URL, key)
	if err != nil {
		t.Fatal("fail to initialize Vault envelope service", err)
	}

	cipher, err := service.Encrypt([]byte(sampleText))
	if err != nil {
		t.Fatal("fail to encrypt data with Vault", err)
	}

	// Create a service with only new key
	newKey := "new-" + key
	newService, err := serviceTestFactory(configOneKey, server.URL, newKey)
	if err != nil {
		t.Fatal("fail to initialize Vault envelope service", err)
	}

	_, err = newService.Decrypt(cipher)
	if err == nil {
		t.Fatal("should fail to decrypt cipher that has no match key")
	}
}

func serviceTestFactory(config, url string, keys ...string) (envelope.Service, error) {
	config = strings.Replace(config, "@url@", url, 1)
	for _, key := range keys {
		config = strings.Replace(config, "@key@", key, 1)
	}
	return VaultKMSFactory(strings.NewReader(config))
}
