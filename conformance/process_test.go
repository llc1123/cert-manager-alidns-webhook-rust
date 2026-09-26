package conformance

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"k8s.io/client-go/rest"
)

const (
	groupName       = "acme.conformance.test"
	solverName      = "alidns-solver"
	frontProxyName  = "front-proxy-client"
	requestHeaderCM = "/api/v1/namespaces/kube-system/configmaps/extension-apiserver-authentication"
)

// webhookProcess is a running Rust binary plus the trust material a
// kube-apiserver aggregator would hold.
type webhookProcess struct {
	url        string
	servingCA  keyPair
	frontProxy keyPair
	certFile   string
	keyFile    string
}

// startWebhook launches the Rust binary against a fake kube-apiserver serving
// the extension-apiserver-authentication ConfigMap.
func startWebhook(t *testing.T, alidnsEndpoint, accessKeyID, accessKeySecret string) *webhookProcess {
	t.Helper()
	binary := os.Getenv("RUST_BINARY")
	if binary == "" {
		t.Fatal("set RUST_BINARY to the compiled Rust executable")
	}
	dir := t.TempDir()
	process := &webhookProcess{
		servingCA:  newCA(t, "serving-ca"),
		frontProxy: newCA(t, "front-proxy-ca"),
		certFile:   filepath.Join(dir, "tls.crt"),
		keyFile:    filepath.Join(dir, "tls.key"),
	}
	serving := newServingCert(t, process.servingCA)
	writeAtomically(t, process.certFile, serving.certPEM)
	writeAtomically(t, process.keyFile, serving.keyPEM)

	kubeCA := newCA(t, "kube-ca")
	kubeconfig := filepath.Join(dir, "kubeconfig")
	writeKubeconfig(t, kubeconfig, newFakeKubeAPI(t, kubeCA, process.frontProxy), kubeCA)

	port := reservePort(t)
	process.url = "https://127.0.0.1:" + port
	cmd := exec.Command(binary)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"GROUP_NAME="+groupName,
		"SOLVER_NAME="+solverName,
		"LISTEN_ADDR=127.0.0.1:"+port,
		"TLS_CERT_FILE="+process.certFile,
		"TLS_KEY_FILE="+process.keyFile,
		"KUBECONFIG="+kubeconfig,
		"ALIDNS_ENDPOINT="+alidnsEndpoint,
		"ALIBABA_CLOUD_ACCESS_KEY_ID="+accessKeyID,
		"ALIBABA_CLOUD_ACCESS_KEY_SECRET="+accessKeySecret,
		"RUST_LOG=info",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start Rust webhook: %v", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-exited })
	process.waitReady(t, exited)
	return process
}

// restConfig mirrors how the aggregator reaches the webhook: the APIService
// caBundle for the server and the front-proxy client certificate.
func (p *webhookProcess) restConfig(client *keyPair) *rest.Config {
	config := &rest.Config{
		Host:            p.url,
		TLSClientConfig: rest.TLSClientConfig{CAData: p.servingCA.certPEM},
		Timeout:         30 * time.Second,
	}
	if client != nil {
		config.CertData, config.KeyData = client.certPEM, client.keyPEM
	}
	return config
}

func (p *webhookProcess) httpClient(t *testing.T, client *keyPair) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(p.servingCA.cert)
	config := &tls.Config{RootCAs: pool}
	if client != nil {
		config.Certificates = []tls.Certificate{client.tlsCertificate(t)}
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: config, ForceAttemptHTTP2: true},
	}
}

func (p *webhookProcess) waitReady(t *testing.T, exited chan error) {
	t.Helper()
	client := p.httpClient(t, nil)
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		select {
		case err := <-exited:
			exited <- err
			t.Fatalf("webhook exited before becoming ready: %v", err)
		default:
		}
		if response, err := client.Get(p.url + "/healthz"); err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("webhook did not become ready: %s", p.url)
}

func newFakeKubeAPI(t *testing.T, kubeCA, frontProxyCA keyPair) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer conformance" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != requestHeaderCM {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata":   map[string]any{"name": "extension-apiserver-authentication", "namespace": "kube-system"},
			"data": map[string]string{
				"requestheader-client-ca-file": string(frontProxyCA.certPEM),
				"requestheader-allowed-names":  `["` + frontProxyName + `"]`,
			},
		})
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{newServingCert(t, kubeCA).tlsCertificate(t)}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func writeKubeconfig(t *testing.T, path string, server *httptest.Server, ca keyPair) {
	t.Helper()
	config := map[string]any{
		"apiVersion":      "v1",
		"kind":            "Config",
		"current-context": "fake",
		"clusters": []any{map[string]any{"name": "fake", "cluster": map[string]any{
			"server": server.URL, "certificate-authority-data": ca.certPEM,
		}}},
		"users":    []any{map[string]any{"name": "fake", "user": map[string]any{"token": "conformance"}}},
		"contexts": []any{map[string]any{"name": "fake", "context": map[string]any{"cluster": "fake", "user": "fake"}}},
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func reservePort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return strconv.Itoa(port)
}
