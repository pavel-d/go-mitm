package mitm

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/getlantern/keyman"
)

const (
	ONE_DAY   = 1
	TWO_WEEKS = ONE_DAY * 14
	ONE_MONTH = 1
	ONE_YEAR  = 1
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

	// ServerTLSConfig: optional configuration for TLS server when MITMing (if nil, a sensible default is used)
	ServerTLSConfig *tls.Config
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
	wrapper.issuingCert, err = keyman.LoadCertificateFromFile(wrapper.cryptoConf.CertFile)
	if err != nil || wrapper.issuingCert.ExpiresBefore(time.Now().AddDate(0, ONE_MONTH, 0)) {
		wrapper.issuingCert, err = wrapper.pk.TLSCertificateFor(
			wrapper.cryptoConf.Organization,
			wrapper.cryptoConf.CommonName,
			time.Now().AddDate(ONE_YEAR, 0, 0),
			true,
			nil)
		if err != nil {
			return fmt.Errorf("Unable to generate self-signed issuing certificate: %s", err)
		}
		wrapper.issuingCert.WriteToFile(wrapper.cryptoConf.CertFile)
	}
	wrapper.issuingCertPem = wrapper.issuingCert.PEMEncoded()
	return
}

func (wrapper *HandlerWrapper) mitmCertForName(name string) (cert *tls.Certificate, err error) {
	wrapper.certMutex.Lock()
	defer wrapper.certMutex.Unlock()

	kpCandidate, found := wrapper.dynamicCerts[name]
	if found {
		return kpCandidate, nil
	}

	generatedCert, err := wrapper.pk.TLSCertificateFor(
		wrapper.cryptoConf.Organization,
		name,
		time.Now().AddDate(0, 0, TWO_WEEKS),
		false,
		wrapper.issuingCert)
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
