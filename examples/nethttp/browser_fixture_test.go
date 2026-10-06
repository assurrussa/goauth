package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type browserFixtureManifest struct {
	Version   int       `json:"version"`
	Purpose   string    `json:"purpose"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	CAHash    string    `json:"caHash"`
}

// The caller creates a fresh private fixture and separately authorizes browser
// trust. No trust store, user profile or certificate warning is modified here.
func browserTLSConfig(root string, now time.Time) (*tls.Config, error) {
	if !filepath.IsAbs(root) || !strings.HasPrefix(filepath.Base(root), "goauth-browser-") {
		return nil, errors.New("absolute dedicated GOAUTH_BROWSER_FIXTURE_DIR is required")
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil || canonical != root {
		return nil, errors.New("browser fixture directory must exist and be canonical")
	}
	for _, entry := range []struct {
		name string
		dir  bool
	}{
		{"", true}, {"chromium-profile", true}, {"fixture.json", false},
		{"ca.pem", false}, {"server.pem", false}, {"server-key.pem", false},
	} {
		info, statErr := os.Lstat(filepath.Join(root, entry.name))
		if statErr != nil {
			return nil, fmt.Errorf("browser fixture %s: %w", entry.name, statErr)
		}
		if info.Mode().Perm()&0o077 != 0 || (entry.dir && !info.IsDir()) || (!entry.dir && !info.Mode().IsRegular()) {
			return nil, fmt.Errorf("browser fixture %s must be private and must not be a symlink", entry.name)
		}
	}
	ca, expiresAt, err := browserFixtureCA(root, now)
	if err != nil {
		return nil, err
	}
	return browserFixtureKeyPair(root, ca, now, expiresAt)
}

func browserFixtureCA(root string, now time.Time) (*x509.Certificate, time.Time, error) {
	data, err := os.ReadFile(filepath.Join(root, "fixture.json"))
	if err != nil {
		return nil, time.Time{}, err
	}
	var manifest browserFixtureManifest
	if err = json.Unmarshal(data, &manifest); err != nil {
		return nil, time.Time{}, fmt.Errorf("browser fixture manifest: %w", err)
	}
	if manifest.Version != 1 || manifest.Purpose != "goauth-browser-acceptance" ||
		now.Before(manifest.CreatedAt) || !now.Before(manifest.ExpiresAt) {
		return nil, time.Time{}, errors.New("browser fixture provenance is outside its explicit validity window")
	}
	caPEM, err := os.ReadFile(filepath.Join(root, "ca.pem"))
	if err != nil {
		return nil, time.Time{}, err
	}
	digest := sha256.Sum256(caPEM)
	if manifest.CAHash != hex.EncodeToString(digest[:]) {
		return nil, time.Time{}, errors.New("browser fixture CA does not match its provenance")
	}
	block, rest := pem.Decode(caPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, time.Time{}, errors.New("browser fixture needs exactly one CA certificate")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, time.Time{}, errors.New("browser fixture CA certificate is invalid")
	}
	if manifest.ExpiresAt.After(ca.NotAfter) {
		return nil, time.Time{}, errors.New("browser fixture validity window exceeds CA validity")
	}
	return ca, manifest.ExpiresAt, nil
}

func browserFixtureKeyPair(root string, ca *x509.Certificate, now, expiresAt time.Time) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(filepath.Join(root, "server.pem"), filepath.Join(root, "server-key.pem"))
	if err != nil {
		return nil, fmt.Errorf("browser fixture certificate/key: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(ca)
	for _, der := range pair.Certificate[1:] {
		intermediate, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			return nil, parseErr
		}
		intermediates.AddCert(intermediate)
	}
	if expiresAt.After(leaf.NotAfter) {
		return nil, errors.New("browser fixture validity window exceeds server certificate validity")
	}
	if leaf.IsCA {
		return nil, errors.New("browser fixture server certificate must not be a CA")
	}
	options := x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, DNSName: "localhost", CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if _, err = leaf.Verify(options); err != nil {
		return nil, fmt.Errorf("browser fixture localhost certificate verification: %w", err)
	}
	if err = leaf.VerifyHostname("127.0.0.1"); err != nil {
		return nil, fmt.Errorf("browser fixture hostile-origin certificate verification: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}, nil
}

type browserFixtureOptions struct {
	wrongCA, wrongKey, expired, wrongHost, missingIP bool
}

func writeBrowserTLSFixture(t *testing.T, now time.Time, options browserFixtureOptions) string {
	t.Helper()
	root, err := os.MkdirTemp(t.TempDir(), "goauth-browser-")
	require.NoError(t, err)
	root, err = filepath.EvalSymlinks(root)
	require.NoError(t, err)
	require.NoError(t, os.Mkdir(filepath.Join(root, "chromium-profile"), 0o700))
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic browser fixture CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Synthetic browser fixture"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if options.expired {
		leaf.NotBefore, leaf.NotAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
	}
	if options.wrongHost {
		leaf.DNSNames = []string{"wrong.example.test"}
	}
	if options.missingIP {
		leaf.IPAddresses = nil
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	if options.wrongCA {
		otherKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, keyErr)
		caDER, err = x509.CreateCertificate(rand.Reader, ca, ca, &otherKey.PublicKey, otherKey)
		require.NoError(t, err)
	}
	if options.wrongKey {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	digest := sha256.Sum256(caPEM)
	manifest, err := json.Marshal(browserFixtureManifest{
		Version: 1, Purpose: "goauth-browser-acceptance", CreatedAt: now,
		ExpiresAt: now.Add(time.Hour).Truncate(time.Second), CAHash: hex.EncodeToString(digest[:]),
	})
	require.NoError(t, err)
	for name, data := range map[string][]byte{
		"fixture.json": manifest, "ca.pem": caPEM,
		"server.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		"server-key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	} {
		require.NoError(t, os.WriteFile(filepath.Join(root, name), data, 0o600))
	}
	return root
}

func TestBrowserTLSFixtureValidation(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name    string
		options browserFixtureOptions
		wantErr bool
	}{
		{"valid", browserFixtureOptions{}, false},
		{"wrong CA", browserFixtureOptions{wrongCA: true}, true},
		{"wrong key", browserFixtureOptions{wrongKey: true}, true},
		{"expired", browserFixtureOptions{expired: true}, true},
		{"wrong hostname", browserFixtureOptions{wrongHost: true}, true},
		{"missing hostile IP", browserFixtureOptions{missingIP: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := browserTLSConfig(writeBrowserTLSFixture(t, now, tc.options), now)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
			require.False(t, cfg.InsecureSkipVerify)
		})
	}
}

func TestBrowserTLSFixtureRejectsMissingStaleAndChangedProvenance(t *testing.T) {
	now := time.Now().UTC()
	_, err := browserTLSConfig("", now)
	require.Error(t, err)
	root := writeBrowserTLSFixture(t, now, browserFixtureOptions{})
	_, err = browserTLSConfig(root, now.Add(5*time.Hour))
	require.ErrorContains(t, err, "provenance")
	require.NoError(t, os.WriteFile(filepath.Join(root, "ca.pem"), []byte("replaced CA"), 0o600))
	_, err = browserTLSConfig(root, now)
	require.ErrorContains(t, err, "provenance")
}
