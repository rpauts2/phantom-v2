// Package tls — ACME DNS-01 prod + lab self-signed.
// Prod: golang.org/x/crypto/acme, TXT через core.DNSProvider (Cloudflare/file).
// Lab: self-signed ECDSA wildcard.
package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/phantom-v2/phantom/core"
	"golang.org/x/crypto/acme"
)

type AutoCert struct {
	CertFile string
	KeyFile  string
	Email    string
	DNS      core.DNSProvider
	Lab      bool // true = self-signed для лабы
	Autocert bool // false = не выпускать: только готовые файлы
}

// certOK: файл валиден ровно под domain и живет дольше 30 дней.
func certOK(certFile, domain string) bool {
	der, err := os.ReadFile(certFile)
	if err != nil {
		return false
	}
	var cert *x509.Certificate
	for {
		var b *pem.Block
		b, der = pem.Decode(der)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			cert = c
			break
		}
	}
	if cert == nil {
		return false
	}
	if time.Now().Add(30*24*time.Hour).After(cert.NotAfter) {
		return false
	}
	for _, n := range cert.DNSNames {
		if n == domain || n == "*."+domain {
			return true
		}
	}
	return cert.Subject.CommonName == domain || cert.Subject.CommonName == "*."+domain
}

var _ core.CertManager = AutoCert{}

func (a AutoCert) EnsureWildcard(ctx context.Context, domain string) error {
	if hasFiles(a.CertFile, a.KeyFile) && certOK(a.CertFile, domain) {
		return nil // готовый валидный серт: переиспользуем, ACME не дергаем
	}
	if a.Lab {
		return selfSignedWildcard(a.CertFile, a.KeyFile, domain)
	}
	if !a.Autocert {
		return fmt.Errorf("autocert off: place valid cert/key for *.%s or enable tls.autocert", domain)
	}
	return acmeWildcard(ctx, a, domain)
}

func hasFiles(cert, key string) bool {
	if _, err := os.Stat(cert); err != nil {
		return false
	}
	_, err := os.Stat(key)
	return err == nil
}

func acmeWildcard(ctx context.Context, a AutoCert, domain string) error {
	if a.Email == "" || strings.Contains(a.Email, "example.com") {
		return fmt.Errorf("acme: set real tls.email for domain %s", domain)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	cl := &acme.Client{DirectoryURL: acme.LetsEncryptURL}
	acc := &acme.Account{Contact: []string{"mailto:" + a.Email}}
	if _, err := cl.Register(ctx, acc, acme.AcceptTOS); err != nil {
		return fmt.Errorf("acme register: %w", err)
	}
	wild := "*." + domain
	z, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(wild, domain))
	if err != nil {
		return fmt.Errorf("acme order: %w", err)
	}
	for _, authURL := range z.AuthzURLs {
		az, err := cl.GetAuthorization(ctx, authURL)
		if err != nil {
			return err
		}
		ch, ok := pickDNS01(az)
		if !ok {
			continue
		}
		txt, err := cl.DNS01ChallengeRecord(ch.Token)
		if err != nil {
			return err
		}
		name := "_acme-challenge." + hostOf(az)
		if err := a.DNS.EnsureTXT(ctx, name, txt); err != nil {
			return fmt.Errorf("dns TXT %s: %w", name, err)
		}
		if _, err := cl.Accept(ctx, ch); err != nil {
			return fmt.Errorf("acme accept: %w", err)
		}
		if _, err := cl.WaitAuthorization(ctx, authURL); err != nil {
			return fmt.Errorf("acme wait: %w", err)
		}
	}
	der, _, err := cl.CreateOrderCert(ctx, z.FinalizeURL, csrDER(key, wild, domain), true)
	if err != nil {
		return fmt.Errorf("acme cert: %w", err)
	}
	return writePair(a.CertFile, a.KeyFile, der, key)
}

func pickDNS01(az *acme.Authorization) (*acme.Challenge, bool) {
	for _, c := range az.Challenges {
		if c.Type == "dns-01" {
			return c, true
		}
	}
	return nil, false
}

func hostOf(az *acme.Authorization) string {
	if az.Identifier.Value != "" {
		return az.Identifier.Value
	}
	return ""
}

func csrDER(key *ecdsa.PrivateKey, names ...string) []byte {
	req := &x509.CertificateRequest{DNSNames: names, Subject: pkix.Name{CommonName: names[0]}}
	der, _ := x509.CreateCertificateRequest(rand.Reader, req, key)
	return der
}

func writePair(certFile, keyFile string, der [][]byte, key *ecdsa.PrivateKey) error {
	if err := os.MkdirAll(filepath.Dir(certFile), 0o750); err != nil {
		return err
	}
	cf, err := os.OpenFile(certFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer cf.Close()
	for _, b := range der {
		if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: b}); err != nil {
			return err
		}
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	kf, err := os.OpenFile(keyFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer kf.Close()
	return pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

func selfSignedWildcard(certFile, keyFile, domain string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: "*." + domain, Organization: []string{"Phantom LAB"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     []string{"*." + domain, domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	return writePair(certFile, keyFile, [][]byte{der}, key)
}

// LoadPair — загрузка для ListenAndServeTLS.
func LoadPair(certFile, keyFile string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certFile, keyFile)
}
