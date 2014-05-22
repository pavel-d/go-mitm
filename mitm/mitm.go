// Package mitm provides a library for adding man-in-the-middle (MITM)
// functionality to any HTTPS server.
package mitm

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/getlantern/go-cache/cache"
	"github.com/getlantern/keyman"
)

const (
	CONNECT = "CONNECT"
)

// HandlerWrapper wraps an http.Handler with MITM'ing functionality
type HandlerWrapper struct {
	cryptoConf      *CryptoConfig
	wrapped         http.Handler
	pk              *keyman.PrivateKey
	pkPem           []byte
	issuingCert     *keyman.Certificate
	issuingCertPem  []byte
	serverTLSConfig *tls.Config
	dynamicCerts    *cache.Cache
	certMutex       sync.Mutex
}

// Wrap creates an http.Handler that wraps the provided handler and MITM's
// CONNECT requests, using the given CryptoConfig.  The primary key and
// certificate used to generate and sign MITM certificates are auto-created if
// not already present.
func Wrap(handler http.Handler, cryptoConf *CryptoConfig) (*HandlerWrapper, error) {
	wrapper := &HandlerWrapper{
		cryptoConf:   cryptoConf,
		wrapped:      handler,
		dynamicCerts: cache.NewCache(),
	}
	err := wrapper.initCrypto()
	if err != nil {
		return nil, err
	}
	return wrapper, nil
}

// ServeHTTP implements ServeHTTP from http.Handler
func (wrapper *HandlerWrapper) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	if req.Method == CONNECT {
		wrapper.intercept(resp, req)
	} else {
		wrapper.wrapped.ServeHTTP(resp, req)
	}
}

// intercept intercepts an HTTP request/response and MITM's the underlying
// connection.
func (wrapper *HandlerWrapper) intercept(resp http.ResponseWriter, req *http.Request) {
	// Find out which host to MITM
	addr := hostIncludingPort(req)
	host := strings.Split(addr, ":")[0]

	// Get/generate a cert for the host
	cert, err := wrapper.mitmCertForName(host)
	if err != nil {
		msg := fmt.Sprintf("Could not get mitm cert for name: %s\nerror: %s", host, err)
		respBadGateway(resp, msg)
		return
	}

	// Hijack the underlying connection and upgrade it to a TLS connection
	connIn, _, err := resp.(http.Hijacker).Hijack()
	if err != nil {
		msg := fmt.Sprintf("Unable to access underlying connection from client: %s", err)
		respBadGateway(resp, msg)
		return
	}
	tlsConfig := makeConfig(wrapper.cryptoConf.ServerTLSConfig)

	// Upgrade to a TLS connection that presents our dynamically generated cert
	// for the HOST
	tlsConfig.Certificates = []tls.Certificate{*cert}
	tlsConnIn := tls.Server(connIn, tlsConfig)

	// This listener allows us to http.Serve on the upgraded TLS connection
	listener := &mitmListener{tlsConnIn}

	// This Handler just fixes up the request URL to have the right protocol and
	// host and then delegates to the wrapped Handler.
	handler := http.HandlerFunc(func(resp2 http.ResponseWriter, req2 *http.Request) {
		// Fix up the request URL to make it look as it would have if the client
		// thought it were talking to a proxy at this point.
		req2.URL.Scheme = "https"
		req2.URL.Host = req2.Host
		wrapper.wrapped.ServeHTTP(resp2, req2)
	})

	// Serve HTTP requests on the upgraded connection.  This will keep reading
	// requests and sending them through our handler as long as the connection
	// stays open.
	go func() {
		err = http.Serve(listener, handler)
		if err != nil && err != io.EOF {
			log.Printf("Error serving mitm'ed connection: %s", err)
		}
	}()

	// Tell the client that their CONNECT was okay - client can now try to
	// connect to our MITM'ing HTTP server
	connIn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
}

// makeConfig makes a copy of a tls config if provided. Otherwise returns an
// empty tls config.
func makeConfig(template *tls.Config) *tls.Config {
	tlsConfig := &tls.Config{}
	if template != nil {
		// Copy the provided tlsConfig
		*tlsConfig = *template
	}
	return tlsConfig
}

func hostIncludingPort(req *http.Request) (host string) {
	host = req.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}
	return
}

func respBadGateway(resp http.ResponseWriter, msg string) {
	log.Println(msg)
	resp.WriteHeader(502)
	resp.Write([]byte(msg))
}
