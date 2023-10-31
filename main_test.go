package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"path"
	"runtime"
	"testing"
)

var exampleDir string

var cert_rsa = tlsCert("RSA")
var cert_p256 = tlsCert("P256")
var cert_p384 = tlsCert("P384")

func init() {
	// include code that only runs when *verbose = true
	*verbose = true

	_, p, _, _ := runtime.Caller(0)
	exampleDir = path.Join(path.Dir(p), "example")
}

func TestCheckOwnerOnly(t *testing.T) {
	path := "/tmp/main_test.tmp"
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatalf(`Failed to create test file with mod 0644: %v`, err)
	}
	defer os.Remove(path)
	if err := checkOwnerOnly(path); err == nil {
		t.Fatalf(`checkOwnerOnly(%q) did not return error on file mod 0644`, path)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatalf(`Failed to change mode: %v`, err)
	}
	if err := checkOwnerOnly(path); err != nil {
		t.Fatalf(`checkOwnerOnly(%q) = %v, want <nil>`, path, err)
	}
}

func TestExpandPath(t *testing.T) {
	if path, err := expandPath("~"); err != nil || path[0] == '~' {
		t.Fatalf(`expandPath("~") = %q, %v, want path not starting with "~"`, path, err)
	}
	if path, err := expandPath("~/foo"); err != nil || path[0] == '~' {
		t.Fatalf(`expandPath("~") = %q, %v, want path not starting with "~"`, path, err)
	}
}

func TestPickClientCert(t *testing.T) {
	if _, err := pickClientCert([]tls.Certificate{}, ""); err == nil {
		t.Fatalf("err is nil")
	}

	certs := []tls.Certificate{
		{Leaf: &x509.Certificate{Subject: pkix.Name{CommonName: "foo"}}},
		{Leaf: &x509.Certificate{Subject: pkix.Name{CommonName: "Yubico PIV Attestation"}}},
	}
	if cert, err := pickClientCert(certs, ""); err != nil || cert.Leaf != certs[0].Leaf {
		t.Fatalf("default cert not found")
	}
	if cert, err := pickClientCert(certs, "foo"); err != nil || cert.Leaf != certs[0].Leaf {
		t.Fatalf("cert with specific CN not found")
	}

	reversed := []tls.Certificate{certs[1], certs[0]}
	if cert, err := pickClientCert(certs, ""); err != nil || cert.Leaf != reversed[1].Leaf {
		t.Fatalf("default cert not found")
	}
	if cert, err := pickClientCert(certs, "foo"); err != nil || cert.Leaf != reversed[1].Leaf {
		t.Fatalf("cert with specific CN not found")
	}

	ambiguous := []tls.Certificate{
		{Leaf: &x509.Certificate{Subject: pkix.Name{CommonName: "foo"}}},
		{Leaf: &x509.Certificate{Subject: pkix.Name{CommonName: "bar"}}},
	}
	if cert, err := pickClientCert(ambiguous, ""); err == nil {
		t.Fatalf("unexpected cert found: %v", cert.Leaf.Subject.CommonName)
	}
}

func TestParseConfig(t *testing.T) {
	if _, _, err := parseConfig("not-found"); err == nil {
		t.Fatalf("err is nil")
	}
	configPath := path.Join(exampleDir, "crypto11.config.yubikey")
	config, crypto11Config, err := parseConfig(configPath)
	if err != nil {
		t.Fatalf("failed to parse crypto11.config.yubikey")
	}
	if config.CommonName != "foo" {
		t.Fatalf("unexpected CommonName in config")
	}
	if crypto11Config.Pin != "123456" {
		t.Fatalf("unexpected Pin in config")
	}
}

func TestHashFile(t *testing.T) {
	if _, err := hashFile("not-found"); err == nil {
		t.Fatalf("err is nil")
	}
	dataFile := path.Join(exampleDir, "crypto11.config.yubikey")
	digest, err := hashFile(dataFile)
	if err != nil {
		t.Fatalf("sha256File failed with crypto11.config.yubikey")
	}
	if hex.EncodeToString(digest) != "da8c5c595f2ab9893dd5bc6df8e8b7dcfad262ecc0593cb2b31dd6f4c9918823" {
		t.Fatalf("unexpected SHA256 digest returned for crypto11.config.yubikey")
	}
}

func TestGetHashFuncion(t *testing.T) {
	publicKey := cert_p384.PrivateKey.(*ecdsa.PrivateKey).Public().(*ecdsa.PublicKey)
	hash := getHashFunction(*publicKey)
	if hash != crypto.SHA384 {
		t.Fatal("unexpected hash function returned")
	}

	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	defer func() {
		if recover() == nil {
			t.Fatal("failed to detect unsupported elliptic curve")
		}
	}()
	getHashFunction(p521.PublicKey)
}

func TestSignAndVerifyFile(t *testing.T) {
	err := signFile(&cert_p256, "example/crypto11.config.yubikey", "example/crypto11.config.yubikey.sig")
	if err != nil {
		t.Fatal(err)
	}
	err = verifySignature(&cert_p256, "example/crypto11.config.yubikey", "example/crypto11.config.yubikey.sig")
	if err != nil {
		t.Fatal("failed to verify signature")
	}
	err = verifySignature(&cert_rsa, "example/crypto11.config.yubikey", "example/crypto11.config.yubikey.sig")
	if err == nil {
		t.Fatal("expected bad signature to be reported")
	}
}

func TestExportPublicKey(t *testing.T) {
	err := exportPublicKey(&cert_rsa, "example/public_key.pem")
	if err != nil {
		t.Fatal(err)
	}
}

// HELPER FUNCTIONS
func tlsCert(alg string) tls.Certificate {
	cert, raw, privateKey := generateCert(alg)
	return tls.Certificate{
		Certificate: [][]byte{raw},
		PrivateKey:  privateKey,
		Leaf:        &cert,
	}
}

func generateCert(alg string) (x509.Certificate, []byte, any) {
	privateKey, err := generateKey(alg)
	if err != nil {
		panic(err)
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1))
	if err != nil {
		panic(err)
	}

	parent := x509.Certificate{
		SerialNumber: serialNumber,
	}
	generated, err := x509.CreateCertificate(rand.Reader, &parent, &parent, getPublicKey(privateKey), privateKey)
	if err != nil {
		panic(err)
	}

	return parent, generated, privateKey
}

func generateKey(alg string) (any, error) {
	switch alg {
	case "RSA":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "P256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		panic("unsupported algorithm provided")
	}
}

func getPublicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}
