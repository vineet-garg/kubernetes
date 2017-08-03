package vault

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/pborman/uuid"
)

const (
	cafile     = "testdata/ca.crt"
	serverCert = "testdata/server.crt"
	serverKey  = "testdata/server.key"
	clientCert = "testdata/client.crt"
	clientKey  = "testdata/client.key"
)

func TestTokenAuth(t *testing.T) {
	config := &VaultEnvelopeConfig{
		Token: uuid.NewRandom().String(),
	}
	encryptAndDecrypt(t, config)
}

func TestTlsAuth(t *testing.T) {
	config := &VaultEnvelopeConfig{
		ClientCert: clientCert,
		ClientKey:  clientKey,
	}
	encryptAndDecrypt(t, config)
}

func TestAppRoleAuth(t *testing.T) {
	config := &VaultEnvelopeConfig{
		RoleId: uuid.NewRandom().String(),
	}
	encryptAndDecrypt(t, config)
}

func encryptAndDecrypt(t *testing.T, config *VaultEnvelopeConfig) {
	server := VaultTestServer(t)
	defer server.Close()

	config.Address = server.URL
	config.CACert = cafile

	client, err := newClientWrapper(config)
	if err != nil {
		t.Fatal("fail to initialize Vault client:", err)
	}

	key := "key"
	text := "hello"

	cipher, err := client.encrypt(key, text)
	if err != nil {
		t.Fatal("fail to encrypt text:", err)
	}
	if !strings.HasPrefix(cipher, "vault:v1:") {
		t.Fatalf("invalid cipher text: %s", cipher)
	}

	plain, err := client.decrypt(key, cipher)
	if err != nil {
		t.Fatal("fail to decrypt text:", err)
	}
	if text != plain {
		t.Fatal("expect %s, but %s", text, plain)
	}
}

func TestClientNegatives(t *testing.T) {
	server := VaultTestServer(t)
	defer server.Close()

	// 1. No Authentication info
	config := &VaultEnvelopeConfig{
		Address: server.URL,
		CACert:  cafile,
	}
	client, err := newClientWrapper(config)
	if err == nil {
		t.Errorf("no expected error for no authentication client, %+v", client)
	}

	// 2. Invalid tls authentication
	config = &VaultEnvelopeConfig{
		Address:    server.URL,
		CACert:     cafile,
		ClientCert: clientCert,
	}
	client, err = newClientWrapper(config)
	if err == nil {
		t.Errorf("no expected error for tls auth no client key, %+v", client)
	}
	config = &VaultEnvelopeConfig{
		Address:   server.URL,
		CACert:    cafile,
		ClientKey: clientKey,
	}
	client, err = newClientWrapper(config)
	if err == nil {
		t.Errorf("no expected error for tls auth no client cert, %+v", client)
	}

	// 3. Invalid app role authentication
	config = &VaultEnvelopeConfig{
		Address:  server.URL,
		CACert:   cafile,
		SecretId: uuid.NewRandom().String(),
	}
	client, err = newClientWrapper(config)
	if err == nil {
		t.Errorf("no expected error for approle auth no role id, %+v", client)
	}

	// 4. More than one authentication info
	config = &VaultEnvelopeConfig{
		Address: server.URL,
		CACert:  cafile,
		Token:   uuid.NewRandom().String(),
		RoleId:  uuid.NewRandom().String(),
	}
	client, err = newClientWrapper(config)
	if err == nil {
		t.Errorf("no expected error for more than one authentications, %+v", client)
	}
}

func VaultTestServer(tb testing.TB) *httptest.Server {
	mux := http.NewServeMux()
	mux.Handle("/v1/transit/encrypt/", &encryptHandler{tb})
	mux.Handle("/v1/transit/decrypt/", &decryptHandler{tb})
	mux.Handle("/v1/auth/cert/login", &tlsLoginHandler{tb})
	mux.Handle("/v1/auth/approle/login", &approleLoginHandler{tb})
	//	server := httptest.NewServer(mux)
	server := httptest.NewUnstartedServer(mux)

	cert, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		tb.Fatal("bad server cert and keys: ", err)
	}
	certs := []tls.Certificate{cert}

	ca, err := ioutil.ReadFile(cafile)
	if err != nil {
		tb.Fatal("bad ca file: ", err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(ca) {
		tb.Fatal("failed to append certificates to pool.")
	}

	server.TLS = &tls.Config{Certificates: certs, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: certPool}
	server.StartTLS()

	return server
}

type encryptHandler struct {
	tb testing.TB
}

// Just prepend "vault:v1:" prefix as encrypted text.
func (h *encryptHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Vault-Token")
	if token == "" {
		h.tb.Fatal("unauthenticated encrypt request.")
	}

	msg, err := parseRequest(r)
	if err != nil {
		h.tb.Error("error request message for encrypt request: ", err)
	}

	plain := msg["plaintext"].(string)
	data := map[string]interface{}{
		"ciphertext": "vault:v1:" + plain,
	}
	buildResponse(w, data)
}

type decryptHandler struct {
	tb testing.TB
}

// Remove the prefix to decrypt the text.
func (h *decryptHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Vault-Token")
	if token == "" {
		h.tb.Fatal("unauthenticated decrypt request.")
	}

	msg, err := parseRequest(r)
	if err != nil {
		h.tb.Error("error request message for decrypt request: ", err)
	}

	cipher := msg["ciphertext"].(string)
	data := map[string]interface{}{
		"plaintext": strings.TrimPrefix(cipher, "vault:v1:"),
	}
	buildResponse(w, data)
}

type tlsLoginHandler struct {
	tb testing.TB
}

// Ensure there is client certificate for tls login
func (h *tlsLoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(r.TLS.PeerCertificates) < 1 {
		h.tb.Error("the tls login doesn't contain valid client certificate.")
	}

	buildAuthResponse(w)
}

type approleLoginHandler struct {
	tb testing.TB
}

// Ensure the request contains role id.
func (h *approleLoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	msg, err := parseRequest(r)
	if err != nil {
		h.tb.Error("error request message for approle login: ", err)
	}

	roleId := msg["role_id"].(string)
	if roleId == "" {
		h.tb.Error("the approle login doesn't contain valid role id.")
	}

	buildAuthResponse(w)
}

// The request message is always json message
func parseRequest(r *http.Request) (map[string]interface{}, error) {
	var msg map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&msg)
	return msg, err
}

// Response for encrypt and decrypt
func buildResponse(w http.ResponseWriter, data map[string]interface{}) {
	secret := api.Secret{
		RequestID: uuid.NewRandom().String(),
		Data:      data,
	}

	json.NewEncoder(w).Encode(&secret)
}

// Response for login request, a client token is generated.
func buildAuthResponse(w http.ResponseWriter) {
	secret := api.Secret{
		RequestID: uuid.NewRandom().String(),
		Auth:      &api.SecretAuth{ClientToken: uuid.NewRandom().String()},
	}

	json.NewEncoder(w).Encode(&secret)
}
