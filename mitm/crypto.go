package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/oxtoacart/keyman"
)

const (
	ONE_WEEK  = 7 * 24 * time.Hour
	TWO_WEEKS = ONE_WEEK * 2
)

// CryptoConfig configures the cryptography settings for an MITMer
type CryptoConfig struct {
	// PKFile: the PEM-encoded file to use as the primary key for this server
	PKFile string

	// CertFile: the PEM-encoded X509 certificate to use for this server (must match PKFile)
	CertFile string

	// Organization: Name of the organization to use on the generated CA cert for this  (defaults to "gomitm")
	Organization string

	// CommonName: CommonName to use on the generated CA cert for this proxy (defaults to "Lantern")
	CommonName string
}

func (wrapper *HandlerWrapper) initCrypto() (err error) {
	if wrapper.cryptoConf.Organization == "" {
		wrapper.cryptoConf.Organization = "gomitm"
	}
	if wrapper.cryptoConf.CommonName == "" {
		wrapper.cryptoConf.CommonName = "Lantern"
	}
	if wrapper.pk, err = keyman.LoadPKFromFile(wrapper.cryptoConf.PKFile); err != nil {
		wrapper.pk, err = keyman.GeneratePK(2048)
		if err != nil {
			return fmt.Errorf("Unable to generate private key: %s", err)
		}
		wrapper.pk.WriteToFile(wrapper.cryptoConf.PKFile)
	}
	wrapper.pkPem = wrapper.pk.PEMEncoded()
	if wrapper.issuingCert, err = keyman.LoadCertificateFromFile(wrapper.cryptoConf.CertFile); err != nil {
		wrapper.issuingCert, err = wrapper.certificateFor("Lantern", nil)
		if err != nil {
			return fmt.Errorf("Unable to generate self-signed issuing certificate: %s", err)
		}
		wrapper.issuingCert.WriteToFile(wrapper.cryptoConf.CertFile)
	}
	wrapper.issuingCertPem = wrapper.issuingCert.PEMEncoded()
	return
}

func (wrapper *HandlerWrapper) certificateFor(name string, issuer *keyman.Certificate) (cert *keyman.Certificate, err error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(int64(time.Now().Nanosecond())),
		Subject: pkix.Name{
			Organization: []string{wrapper.cryptoConf.Organization},
			CommonName:   name,
		},
		NotBefore: now.Add(-1 * ONE_WEEK),
		NotAfter:  now.Add(TWO_WEEKS),

		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	if issuer == nil {
		template.KeyUsage = template.KeyUsage | x509.KeyUsageCertSign
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IsCA = true
	}
	cert, err = wrapper.pk.Certificate(template, issuer)
	return
}

func (wrapper *HandlerWrapper) mitmCertForName(name string) (cert *tls.Certificate, err error) {
	wrapper.certMutex.Lock()
	defer wrapper.certMutex.Unlock()
	kpCandidate, found := wrapper.dynamicCerts[name]
	if found {
		return kpCandidate, nil
	}
	generatedCert, err := wrapper.certificateFor(name, wrapper.issuingCert)
	if err != nil {
		return nil, fmt.Errorf("Unable to issue certificate: %s", err)
	}
	keyPair, err := tls.X509KeyPair(generatedCert.PEMEncoded(), wrapper.pkPem)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse keypair for tls: %s", err)
	}
	wrapper.dynamicCerts[name] = &keyPair
	return &keyPair, nil
}
