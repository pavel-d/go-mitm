// Package mitm provides a library for adding man-in-the-middle (MITM)
// functionality to any HTTPS server.
package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/oxtoacart/keyman"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	ONE_WEEK  = 7 * 24 * time.Hour
	TWO_WEEKS = ONE_WEEK * 2

	PK_FILE   = "proxypk.pem"
	CERT_FILE = "proxycert.pem"
)

type Proxy struct {
	// PKFile: the PEM-encoded file to use as the primary key for this server
	PKFile string

	// CertFile: the PEM-encoded X509 certificate to use for this server (must match PKFile)
	CertFile string

	// Organization: Name of the organization to use on the generated CA cert for this proxy
	Organization string

	// CommonName: CommonName to use on the generated CA cert for this proxy
	CommonName string

	pk             *keyman.PrivateKey
	pkPem          []byte
	issuingCert    *keyman.Certificate
	issuingCertPem []byte
	dynamicCerts   map[string]*tls.Certificate
	certMutex      sync.Mutex
}

// NewProxy creates a new Proxy using primary key and certificate at the
// specified paths.  If no primary key and/or certificate can be found at the
// given paths, they will be automatically generated.
func NewProxy(pkFile string, certFile string) (proxy *Proxy, err error) {
	proxy = &Proxy{
		PKFile:       pkFile,
		CertFile:     certFile,
		Organization: "gomitm",
		dynamicCerts: make(map[string]*tls.Certificate),
	}
	if proxy.pk, err = keyman.LoadPKFromFile(pkFile); err != nil {
		proxy.pk, err = keyman.GeneratePK(2048)
		if err != nil {
			return nil, fmt.Errorf("Unable to generate private key: %s", err)
		}
		proxy.pk.WriteToFile(PK_FILE)
	}
	proxy.pkPem = proxy.pk.PEMEncoded()
	if proxy.issuingCert, err = keyman.LoadCertificateFromFile(certFile); err != nil {
		proxy.issuingCert, err = proxy.certificateFor("Lantern", nil)
		if err != nil {
			return nil, fmt.Errorf("Unable to generate self-signed issuing certificate: %s", err)
		}
		proxy.issuingCert.WriteToFile(CERT_FILE)
	}
	proxy.issuingCertPem = proxy.issuingCert.PEMEncoded()
	return
}

func (proxy *Proxy) mitmCertForName(name string) (cert *tls.Certificate, err error) {
	proxy.certMutex.Lock()
	defer proxy.certMutex.Unlock()
	kpCandidate, found := proxy.dynamicCerts[name]
	if found {
		return kpCandidate, nil
	}
	generatedCert, err := proxy.certificateFor(name, proxy.issuingCert)
	if err != nil {
		return nil, fmt.Errorf("Unable to issue certificate: %s", err)
	}
	keyPair, err := tls.X509KeyPair(generatedCert.PEMEncoded(), proxy.pkPem)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse keypair for tls: %s", err)
	}
	proxy.dynamicCerts[name] = &keyPair
	return &keyPair, nil
}

// Intercept intercepts the given request and starts mitm'ing it
func (proxy *Proxy) Intercept(resp http.ResponseWriter, req *http.Request) {
	addr := hostIncludingPort(req)
	host := strings.Split(addr, ":")[0]

	connIn, _, err := resp.(http.Hijacker).Hijack()
	if err != nil {
		msg := fmt.Sprintf("Unable to access underlying connection from client: %s", err)
		respondBadGateway(resp, req, msg)
		return
	}
	connOut, err := tls.Dial("tcp", addr, &tls.Config{})
	if err != nil {
		msg := fmt.Sprintf("Unable to dial server: %s", err)
		respondBadGateway(resp, req, msg)
		return
	}
	cert, err := proxy.mitmCertForName(host)
	if err != nil {
		msg := fmt.Sprintf("Could not get mitm cert for name: %s\nerror: %s", host, err)
		respondBadGateway(resp, req, msg)
		return
	}
	tlsConnIn := tls.Server(connIn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	pipe(tlsConnIn, connOut)
	connIn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
}

func (proxy *Proxy) certificateFor(name string, issuer *keyman.Certificate) (cert *keyman.Certificate, err error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(int64(time.Now().Nanosecond())),
		Subject: pkix.Name{
			Organization: []string{proxy.Organization},
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
	cert, err = proxy.pk.Certificate(template, issuer)
	return
}

func hostIncludingPort(req *http.Request) (host string) {
	host = req.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}
	return
}

func respondBadGateway(resp http.ResponseWriter, req *http.Request, msg string) {
	resp.WriteHeader(502)
	resp.Write([]byte(fmt.Sprintf("Bad Gateway: %s - %s", req.URL, msg)))
}

func pipe(connIn net.Conn, connOut net.Conn) {
	go func() {
		defer connIn.Close()
		io.Copy(connOut, connIn)
	}()
	go func() {
		defer connOut.Close()
		io.Copy(connIn, connOut)
	}()
}
