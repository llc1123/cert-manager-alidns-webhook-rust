package conformance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type keyPair struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
}

func (k keyPair) tlsCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	pair, err := tls.X509KeyPair(k.certPEM, k.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func newCA(t *testing.T, name string) keyPair {
	t.Helper()
	return issue(t, nil, &x509.Certificate{
		Subject:               pkix.Name{CommonName: name},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	})
}

func newServingCert(t *testing.T, ca keyPair) keyPair {
	t.Helper()
	return issue(t, &ca, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "alidns-webhook"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:    []string{"localhost"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
}

func newClientCert(t *testing.T, ca keyPair, commonName string) keyPair {
	t.Helper()
	return issue(t, &ca, &x509.Certificate{
		Subject:     pkix.Name{CommonName: commonName},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
}

func issue(t *testing.T, parent *keyPair, template *x509.Certificate) keyPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template.SerialNumber = serial
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(24 * time.Hour)
	signer, signerCert := key, template
	if parent != nil {
		signer, signerCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signerCert, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return keyPair{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

// writeAtomically replaces path via rename, like kubelet's projected volumes.
func writeAtomically(t *testing.T, path string, data []byte) {
	t.Helper()
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}
