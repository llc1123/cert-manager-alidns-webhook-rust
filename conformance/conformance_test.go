package conformance

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"slices"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"

	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/webhook"
)

// solver is cert-manager's own DNS01 webhook client, configured the way the
// aggregator would reach the Rust binary.
func solver(t *testing.T, process *webhookProcess, client *keyPair) *webhook.Webhook {
	t.Helper()
	hook := &webhook.Webhook{}
	if err := hook.Initialize(process.restConfig(client), nil); err != nil {
		t.Fatal(err)
	}
	return hook
}

// challenge builds a ChallengeRequest the way cert-manager does for this solver.
func challenge(zone, fqdn, key string) *whapi.ChallengeRequest {
	return &whapi.ChallengeRequest{
		UID:               types.UID("uid-" + nonce()),
		Type:              "dns-01",
		DNSName:           strings.TrimPrefix(strings.TrimSuffix(fqdn, "."), "_acme-challenge."),
		Key:               key,
		ResourceNamespace: "default",
		ResolvedFQDN:      fqdn,
		ResolvedZone:      zone,
		Config: &apiextensionsv1.JSON{
			Raw: []byte(`{"groupName":"` + groupName + `","solverName":"` + solverName + `","config":{}}`),
		},
	}
}

// nonce returns a random hex string for unique names and keys.
func nonce() string {
	var value [6]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(value[:])
}

func TestPresentAndCleanUp(t *testing.T) {
	target := newTarget(t)
	hook := solver(t, target.process, &target.client)
	fqdn := "_acme-challenge.present-" + nonce() + "." + target.zone
	ch := challenge(target.zone, fqdn, "key-"+nonce())

	for range 2 {
		if err := hook.Present(ch); err != nil {
			t.Fatalf("Present: %v", err)
		}
	}
	target.backend.waitPresent(t, ch.ResolvedFQDN, ch.Key)
	target.backend.assertSingle(t, ch.ResolvedFQDN, ch.Key)
	for range 2 {
		if err := hook.CleanUp(ch); err != nil {
			t.Fatalf("CleanUp: %v", err)
		}
	}
	target.backend.waitAbsent(t, ch.ResolvedFQDN, ch.Key)
}

// Mirrors cert-manager's TestExtendedDeletingOneRecordRetainsOthers.
func TestDeletingOneRecordRetainsOthers(t *testing.T) {
	target := newTarget(t)
	hook := solver(t, target.process, &target.client)
	fqdn := "_acme-challenge.multi-" + nonce() + "." + target.zone
	first := challenge(target.zone, fqdn, "first-"+nonce())
	second := challenge(target.zone, fqdn, "second-"+nonce())
	for _, ch := range []*whapi.ChallengeRequest{first, second} {
		if err := hook.Present(ch); err != nil {
			t.Fatalf("Present: %v", err)
		}
		t.Cleanup(func() { _ = hook.CleanUp(ch) })
	}
	target.backend.waitPresent(t, fqdn, first.Key)
	target.backend.waitPresent(t, fqdn, second.Key)
	if err := hook.CleanUp(second); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	target.backend.waitAbsent(t, fqdn, second.Key)
	target.backend.waitPresent(t, fqdn, first.Key)
}

func TestProviderErrorReachesCertManager(t *testing.T) {
	target := newTarget(t)
	hook := solver(t, target.process, &target.client)
	zone := "not-hosted-" + nonce() + ".invalid."
	err := hook.Present(challenge(zone, "_acme-challenge."+zone, "key"))
	if err == nil || !strings.Contains(err.Error(), "AliDNS") {
		t.Fatalf("expected an AliDNS error surfaced through cert-manager, got %v", err)
	}
}

func TestDiscoveryAdvertisesSolver(t *testing.T) {
	target := newTarget(t)
	client, err := discovery.NewDiscoveryClientForConfig(target.process.restConfig(&target.client))
	if err != nil {
		t.Fatal(err)
	}
	resources, err := client.ServerResourcesForGroupVersion(groupName + "/v1alpha1")
	if err != nil {
		t.Fatal(err)
	}
	if len(resources.APIResources) != 1 {
		t.Fatalf("unexpected resources: %#v", resources.APIResources)
	}
	resource := resources.APIResources[0]
	if resource.Name != solverName || resource.Kind != "ChallengePayload" || resource.Namespaced ||
		!slices.Equal(resource.Verbs, []string{"create"}) {
		t.Fatalf("unexpected resource: %#v", resource)
	}
}

func TestOnlyFrontProxyClientsAreServed(t *testing.T) {
	target := newTarget(t)
	process := target.process
	discoveryURL := process.url + "/apis/" + groupName + "/v1alpha1"

	response, err := process.httpClient(t, &target.client).Get(discoveryURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ProtoMajor != 2 {
		t.Fatalf("front-proxy client: got %s over HTTP/%d", response.Status, response.ProtoMajor)
	}

	wrongName := newClientCert(t, process.frontProxy, "system:anonymous")
	for name, client := range map[string]*keyPair{"no client certificate": nil, "disallowed common name": &wrongName} {
		response, err := process.httpClient(t, client).Get(discoveryURL)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: expected 401, got %s", name, response.Status)
		}
		if err := solver(t, process, client).Present(challenge(target.zone, "_acme-challenge."+target.zone, "k")); err == nil {
			t.Fatalf("%s: cert-manager Present unexpectedly succeeded", name)
		}
	}

	// Force-send a chain the server did not ask for; the handshake must fail.
	foreign := newClientCert(t, newCA(t, "foreign-ca"), frontProxyName).tlsCertificate(t)
	forced := process.httpClient(t, nil)
	forced.Transport.(*http.Transport).TLSClientConfig.GetClientCertificate =
		func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &foreign, nil }
	if response, err := forced.Get(discoveryURL); err == nil {
		_ = response.Body.Close()
		t.Fatalf("certificate from an untrusted CA was accepted: %s", response.Status)
	}

	response, err = process.httpClient(t, nil).Get(process.url + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("healthz without client certificate: %s", response.Status)
	}
}

func TestServingCertificateRotation(t *testing.T) {
	target := newTarget(t)
	process := target.process
	rotated := newServingCert(t, process.servingCA)
	writeAtomically(t, process.keyFile, rotated.keyPEM)
	writeAtomically(t, process.certFile, rotated.certPEM)

	conn, err := tls.Dial("tcp", strings.TrimPrefix(process.url, "https://"), &tls.Config{
		RootCAs:    process.httpClient(t, nil).Transport.(*http.Transport).TLSClientConfig.RootCAs,
		ServerName: "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	served := conn.ConnectionState().PeerCertificates[0]
	if served.SerialNumber.Cmp(rotated.cert.SerialNumber) != 0 {
		t.Fatal("new connection was not served the rotated certificate")
	}
}
