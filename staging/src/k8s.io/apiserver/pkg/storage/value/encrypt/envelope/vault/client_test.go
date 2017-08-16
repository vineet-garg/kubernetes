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
	server := VaultTestServer(t, nil)
	defer server.Close()

	config := &VaultEnvelopeConfig{
		Token:   uuid.NewRandom().String(),
		Address: server.URL,
		CACert:  cafile,
	}
	encryptAndDecrypt(t, config)
}

func TestTlsAuth(t *testing.T) {
	server := VaultTestServer(t, nil)
	defer server.Close()

	config := &VaultEnvelopeConfig{
		ClientCert: clientCert,
		ClientKey:  clientKey,
		Address:    server.URL,
		CACert:     cafile,
	}
	encryptAndDecrypt(t, config)
}

func TestAppRoleAuth(t *testing.T) {
	server := VaultTestServer(t, nil)
	defer server.Close()

	config := &VaultEnvelopeConfig{
		RoleId:  uuid.NewRandom().String(),
		Address: server.URL,
		CACert:  cafile,
	}
	encryptAndDecrypt(t, config)
}

func TestCustomTransitPath(t *testing.T) {
	customTransitPath := "custom-transit"
	server := customTransitPathServer(t, customTransitPath)
	defer server.Close()

	config := &VaultEnvelopeConfig{
		Token:   uuid.NewRandom().String(),
		Address: server.URL,
		CACert:  cafile,
	}
        
	validTransitPaths := []string{customTransitPath, "/" + customTransitPath, customTransitPath + "/", "/" + customTransitPath + "/"}
	for _, path := range validTransitPaths {
		config.TransitPath = path
		encryptAndDecrypt(t, config)
	}
       
	// Invalid transit path will result 404 error
	config.TransitPath = "invalid-" + customTransitPath
	client, err := newClientWrapper(config)
	if err != nil {
		t.Fatal("fail to initialize Vault client:", err)
	}

	_, err = client.encrypt("key", "text")
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Error("should get 404 error for non-existed transit path")
	}

	_, err = client.decrypt("key", "text")
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Error("should get 404 error for non-existed transit path")
	}

}
   
func TestCustomAuthPath(t *testing.T) {
        customAuthPath := "custom-auth"
        server := customAuthPathServer(t, customAuthPath)
        defer server.Close()

        appRoleConfig := &VaultEnvelopeConfig{
                RoleId:  uuid.NewRandom().String(),
                Address: server.URL,
                CACert:  cafile,
        }
        
        validAuthPaths := []string{customAuthPath, "/" + customAuthPath, customAuthPath + "/", "/" + customAuthPath + "/"}
        for _, path := range validAuthPaths {
                appRoleConfig.AuthPath = path
                encryptAndDecrypt(t, appRoleConfig)
        }


        // Invalid auth path will result 404 error
        appRoleConfig.AuthPath = "invalid-" + customAuthPath
        _, err := newClientWrapper(appRoleConfig)
        if err == nil {
                t.Error("should fail to initialize Vault client")
        }

}

func customTransitPathServer(t *testing.T, transit string) *httptest.Server {
	handlers := DefaultTestHandlers(t)

	// Replace with custom transit path
	for _, key := range []string{"/v1/transit/encrypt/", "/v1/transit/decrypt/"} {
		newKey := strings.Replace(key, "transit", transit, 1)
		handlers[newKey] = handlers[key]
		delete(handlers, key)
	}
        
	return VaultTestServer(t, handlers)
}

func customAuthPathServer(t *testing.T, auth string) *httptest.Server {
        handlers := DefaultTestHandlers(t)

        // Replace with custom auth path
        for _, key := range []string{"/v1/auth/cert/login", "/v1/auth/approle/login"} {
                newKey := strings.Replace(key, "auth", auth, 1)
                handlers[newKey] = handlers[key]
                delete(handlers, key)
        }


        return VaultTestServer(t, handlers)
}

func encryptAndDecrypt(t *testing.T, config *VaultEnvelopeConfig) {
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

func VaultTestServer(tb testing.TB, handlers map[string]http.Handler) *httptest.Server {
	mux := http.NewServeMux()
	if handlers == nil {
		handlers = DefaultTestHandlers(tb)
	}
	for path, handler := range handlers {
		mux.Handle(path, handler)
	}
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

func DefaultTestHandlers(tb testing.TB) map[string]http.Handler {
	return map[string]http.Handler{
		"/v1/transit/encrypt/":   &encryptHandler{tb},
		"/v1/transit/decrypt/":   &decryptHandler{tb},
		"/v1/auth/cert/login":    &tlsLoginHandler{tb},
		"/v1/auth/approle/login": &approleLoginHandler{tb},
	}
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
