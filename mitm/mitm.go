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
	"net/http/httputil"
	"strings"
	"sync"
	"time"
)

const (
	ONE_WEEK  = 7 * 24 * time.Hour
	TWO_WEEKS = ONE_WEEK * 2

	PK_FILE   = "proxypk.pem"
	CERT_FILE = "proxycert.pem"

	HTTP_ADDR  = "127.0.0.1:8080"
	HTTPS_ADDR = "127.0.0.1:8081"
)

type Proxy struct {
	PKFile       string
	CertFile     string
	Organization string
	CommonName   string

	addr           string
	pk             *keyman.PrivateKey
	pkPem          []byte
	issuingCert    *keyman.Certificate
	issuingCertPem []byte
	dynamicCerts   map[string]*tls.Certificate
	certMutex      sync.Mutex
}

// NewProxy creates a new Proxy using primary key and certificate at
// the specified paths and listening at the given address.  If no primary key
// and/or certificate can be found at the given paths, they will be
// automatically generated.
func NewProxy(pkFile string, certFile string, addr string) (proxy *Proxy, err error) {
	proxy = &Proxy{
		PKFile:       pkFile,
		CertFile:     certFile,
		Organization: "gomitm",
		addr:         addr,
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

// Start() starts the Proxy, which will listen on the configured Proxy.addr
func (proxy *Proxy) Start() (err chan error) {
	err = make(chan error)

	server := &http.Server{
		TLSConfig: &tls.Config{
			CertificateForName: func(name string) (cert *tls.Certificate, err error) {
				proxy.certMutex.Lock()
				defer proxy.certMutex.Unlock()
				kpCandidate, ok := proxy.dynamicCerts[name]
				if ok {
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
			},
		},
		Addr:         proxy.addr,
		Handler:      http.HandlerFunc(proxy.handleRequest),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		if _err := server.ListenAndServeTLS(proxy.CertFile, proxy.PKFile); _err != nil {
			err <- fmt.Errorf("Unable to start HTTPS proxy: %s", err)
		}
		err <- nil
	}()

	return
}

// Intercept intercepts the given request and starts mitm'ing it
func (proxy *Proxy) Intercept(resp http.ResponseWriter, req *http.Request) {
	if connIn, _, err := resp.(http.Hijacker).Hijack(); err != nil {
		msg := fmt.Sprintf("Unable to access underlying connection from client: %s", err)
		respondBadGateway(resp, req, msg)
	} else {
		connOut, err := net.Dial("tcp", proxy.addr)
		if err != nil {
			msg := fmt.Sprintf("Unable to dial server: %s", err)
			respondBadGateway(resp, req, msg)
		} else {
			pipe(connIn, connOut)
			connIn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
		}
	}
}

func (proxy *Proxy) handleRequest(resp http.ResponseWriter, req *http.Request) {
	rp := httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// Transform the URL into an absolute URL including protocol (for downstream proxy)
			host := hostIncludingPort(req)
			req.URL.Scheme = "https"
			req.URL.Host = host
		},
	}
	rp.ServeHTTP(resp, req)
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
