// Copyright (c) 2023 Volvo Car Corporation
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/ThalesIgnite/crypto11"
	"golang.org/x/term"
)

const usageFormat = `SYNOPSIS

%[1]s [FLAGS] sign <filename> [sigfile]
%[1]s [FLAGS] verify <filename> [sigfile]
%[1]s [FLAGS] pubkey [filename]

DESCRIPTION

Dead-simple utility to sign and verify files/signatures with
your key-pair bound to your X509 Certificate (RSA or ECC) on
your connected PKCS#11 device.

The sign sub-command signs the given file. Actually the given file is first
hashed and then signed. By default the file is hashed with SHA256 but other
functions are supported. The sigfile positional argument can be
omitted, in which case filename.sig is implied. Pass "-" as sigfile
to get the signature (binary) written to STDOUT.

The verify sub-command verifies the given file and signature (from sigfile).
The sigfile positional argument can be omitted, in which case filename.sig
is implied.

The pubkey sub-command exports the public key from the PKCS#11 devices
so that signatures can be verified with other tools (e.g. openssl).
If filename is omitted the pubkey will be written to STDOUT.

SECURITY

All sensitive cryptographic operations are executed safely on the
connected PKCS#11 device.

The file content is first hashed and it is the resulting digest
that is actually signed/verified.

RSA signatures are PSS padded with salt length == hash length (256-bits).

FLAGS
`

// https://developers.yubico.com/yubico-piv-tool/Actions/signing.html
var SUPPORTED_HASH_FUNCTIONS = map[string]crypto.Hash{
	"SHA1":   crypto.SHA1,
	"SHA256": crypto.SHA256,
	"SHA384": crypto.SHA384,
	"SHA512": crypto.SHA512,
}

type Config struct {
	// X509 CN for picking the right Cert
	CommonName string
}

var verbose = flag.Bool(
	"verbose", false, "be verbose about what is going on",
)

var crypto11ConfigPath = flag.String(
	"crypto11Config", "~/.crypto11.json",
	"path to github.com/ThalesIgnite/crypto11 PKCS#11 config file",
)

var hashFunction = flag.String(
	"hashFunction", "SHA256", "hash function (SHA1 | SHA256 | SHA384 | SHA512)",
)

var rsaOpts = &rsa.PSSOptions{
	SaltLength: rsa.PSSSaltLengthEqualsHash,
	Hash:       crypto.SHA256,
}

func verbosePrintf(format string, args ...interface{}) {
	if *verbose {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

func failOnError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func checkOwnerOnly(path string) error {
	fileinfo, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fileinfo.Mode() != 0600 {
		return fmt.Errorf("%s has invalid mod (expecting 0600)", path)
	}
	return nil
}

func expandPath(path string) (string, error) {
	usr, err := user.Current()
	if err != nil {
		return path, err
	}
	expandedPath := path
	if path == "~" {
		// In case of "~", which won't be caught by the "else if"
		expandedPath = usr.HomeDir
	} else if strings.HasPrefix(path, "~/") {
		// Use strings.HasPrefix so we don't match paths like
		// "/something/~/something/"
		expandedPath = filepath.Join(usr.HomeDir, path[2:])
	}
	return expandedPath, nil
}

func pickClientCert(certs []tls.Certificate, commonName string) (*tls.Certificate, error) {
	// just print all certs on device
	if *verbose {
		for _, c := range certs {
			verbosePrintf("found cert %q (serial: %x)\n",
				c.Leaf.Subject.CommonName, c.Leaf.SerialNumber)
		}
	}
	index := -1
	for i, c := range certs {
		cn := c.Leaf.Subject.CommonName
		if cn == commonName {
			return &c, nil
		}
		if strings.Contains(cn, "PIV Attestation") {
			verbosePrintf("ignoring attestation cert: %s\n", cn)
			continue
		}
		if index != -1 {
			return nil, fmt.Errorf(
				"multiple certs found (hint: use the CommonName field to pick one)")
		}
		index = i
	}
	if index == -1 {
		return nil, fmt.Errorf("no certs found on PKCS#11 device")
	}
	return &certs[index], nil
}

func parseConfig(path string) (*Config, *crypto11.Config, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	// load pkcs11gn fields
	var config Config
	err = json.Unmarshal(bytes, &config)
	if err != nil {
		return nil, nil, err
	}

	// load crypto11 fields
	var crypto11Config crypto11.Config
	err = json.Unmarshal(bytes, &crypto11Config)
	if err != nil {
		return nil, nil, err
	}

	return &config, &crypto11Config, err
}

func hashFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	hash := SUPPORTED_HASH_FUNCTIONS[*hashFunction].New()

	// allocate 64 KiB buffer
	buf := make([]byte, 64*1024)
	for {
		var n int
		n, err = f.Read(buf)
		if err != nil {
			break
		}
		hash.Write(buf[:n])
	}
	if err == io.EOF {
		// openssl dgst -<alg> -binary data.txt > data.<alg>
		return hash.Sum(nil), nil
	}
	return nil, err
}

func getHashFunction(key ecdsa.PublicKey) crypto.Hash {
	switch key.Params().Name {
	case "P-256":
		return crypto.SHA256
	case "P-384":
		return crypto.SHA384
	default:
		panic("unsupported public key algorithm")
	}
}

func signFile(cert *tls.Certificate, path string, sigpath string) error {
	digest, err := hashFile(path)
	if err != nil {
		return err
	}

	// get the generic signer interface
	signer := cert.PrivateKey.(crypto.Signer)

	var signature []byte
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		signature, err = signer.Sign(rand.Reader, digest, rsaOpts)
	case *ecdsa.PublicKey:
		publicKey := signer.Public().(*ecdsa.PublicKey)
		signature, err = signer.Sign(rand.Reader, digest, getHashFunction(*publicKey))
	default:
		err = fmt.Errorf("unsupported public key algo: %s", cert.Leaf.PublicKeyAlgorithm)
	}
	if err != nil {
		return err
	}

	if sigpath == "-" {
		// do not let any control chars mess up the signature
		os.Stdout.Write(signature)
		return nil
	}

	return os.WriteFile(sigpath, signature, 0644)
}

func verifySignature(cert *tls.Certificate, path string, sigpath string) error {
	digest, err := hashFile(path)
	if err != nil {
		return err
	}

	signature, err := os.ReadFile(sigpath)
	if err != nil {
		return err
	}

	// get the generic signer interface
	signer := cert.PrivateKey.(crypto.Signer)
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		// openssl pkeyutl -verify -pubin -inkey pubkey.pem -sigfile data.sig -in data.sha256 \
		//	 -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1
		publicKey := signer.Public().(*rsa.PublicKey)
		return rsa.VerifyPSS(publicKey, SUPPORTED_HASH_FUNCTIONS[*hashFunction], digest, signature, rsaOpts)
	case *ecdsa.PublicKey:
		publicKey := signer.Public().(*ecdsa.PublicKey)
		// openssl pkeyutl -verify -pubin -inkey pubkey.pem -sigfile data.sig -in data.sha256|sha384|sha512 \
		//	 -pkeyopt digest:sha256|sha384|sha512
		if valid := ecdsa.VerifyASN1(publicKey, digest, signature); !valid {
			return fmt.Errorf("bad signature encountered")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key algo: %s", cert.Leaf.PublicKeyAlgorithm)
	}
}

func exportPublicKey(cert *tls.Certificate, path string) error {
	signer := cert.PrivateKey.(crypto.Signer)
	bytes, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bytes,
	}
	bytes = pem.EncodeToMemory(block)
	if path == "" {
		fmt.Fprint(os.Stdout, string(bytes))
		return nil
	}
	return os.WriteFile(path, bytes, 0644)
}

func main() {
	// customise flag usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usageFormat, os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	verbosePrintf("crypto11ConfigPath = %s\n", *crypto11ConfigPath)

	if _, supported := SUPPORTED_HASH_FUNCTIONS[*hashFunction]; !supported {
		panic(fmt.Sprintf("unsupported hash function supplied: %s", *hashFunction))
	}
	rsaOpts.Hash = SUPPORTED_HASH_FUNCTIONS[*hashFunction]

	configPath, err := expandPath(*crypto11ConfigPath)
	failOnError(err)

	err = checkOwnerOnly(configPath)
	failOnError(err)

	config, crypto11Config, err := parseConfig(configPath)
	failOnError(err)

	// no PIN in .crypto11.json
	// 1. interactive tty: ask the user for password
	// 2. non-interactive tty: let the crypto11 lib worry about it
	if crypto11Config.Pin == "" && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "PIN: ")
		pin, err := term.ReadPassword(int(os.Stdin.Fd()))
		failOnError(err)
		fmt.Fprintln(os.Stderr)
		crypto11Config.Pin = string(pin)
	}

	crypto11Context, err := crypto11.Configure(crypto11Config)
	failOnError(err)

	clientCerts, err := crypto11Context.FindAllPairedCertificates()
	failOnError(err)

	clientCert, err := pickClientCert(clientCerts, config.CommonName)
	failOnError(err)

	verbosePrintf("using cert \"%s\" (serial: %x)\n",
		clientCert.Leaf.Subject.CommonName, clientCert.Leaf.SerialNumber)

	switch flag.Arg(0) {
	case "sign":
		sigfile := flag.Arg(2)
		if sigfile == "" {
			sigfile = flag.Arg(1) + ".sig"
		}
		err = signFile(clientCert, flag.Arg(1), sigfile)
		if err == nil && sigfile != "-" {
			fmt.Fprintf(os.Stderr, "signature written to %s\n", sigfile)
		}
	case "verify":
		sigfile := flag.Arg(2)
		if sigfile == "" {
			sigfile = flag.Arg(1) + ".sig"
		}
		err = verifySignature(clientCert, flag.Arg(1), sigfile)
		if err == nil {
			fmt.Fprintf(os.Stderr, "valid signature in %s\n", sigfile)
		}
	case "pubkey":
		path := flag.Arg(1)
		err = exportPublicKey(clientCert, path)
		if err == nil && path != "" {
			fmt.Fprintf(os.Stderr, "public key exported to %s\n", path)
		}
	default:
		err = fmt.Errorf("unsupported sub-command: %s", flag.Arg(0))
	}
	failOnError(err)
}
