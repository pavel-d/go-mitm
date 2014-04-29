// Package mitm provides a library for adding man-in-the-middle (MITM)
// functionality to any HTTPS server.
package mitm

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/getlantern/keyman"
)

const (
	CONNECT = "CONNECT"
)

// HandlerWrapper wraps a Handler with MITM'ing functionality
type HandlerWrapper struct {
	cryptoConf     *CryptoConfig
	wrapped        http.Handler
	pk             *keyman.PrivateKey
	pkPem          []byte
	issuingCert    *keyman.Certificate
	issuingCertPem []byte
	dynamicCerts   map[string]*tls.Certificate
	certMutex      sync.Mutex
}

// Wrap creates an http.Handler that wraps the provided handler and MITM's
// CONNECT requests, using the given CryptoConfig.  The primary key and
// certificate used to generate and sign MITM certificates are auto-created if
// not already present.
func Wrap(handler http.Handler, cryptoConf *CryptoConfig) (*HandlerWrapper, error) {
	wrapper := &HandlerWrapper{
		cryptoConf:   cryptoConf,
		wrapped:      handler,
		dynamicCerts: make(map[string]*tls.Certificate),
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

func (wrapper *HandlerWrapper) intercept(resp http.ResponseWriter, req *http.Request) {
	addr := hostIncludingPort(req)
	host := strings.Split(addr, ":")[0]

	cert, err := wrapper.mitmCertForName(host)
	if err != nil {
		msg := fmt.Sprintf("Could not get mitm cert for name: %s\nerror: %s", host, err)
		respBadGateway(resp, msg)
		return
	}

	connIn, _, err := resp.(http.Hijacker).Hijack()
	if err != nil {
		msg := fmt.Sprintf("Unable to access underlying connection from client: %s", err)
		respBadGateway(resp, msg)
		return
	}
	tlsConnIn := tls.Server(connIn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})

	listener := &mitmListener{tlsConnIn}
	handler := http.HandlerFunc(func(resp2 http.ResponseWriter, req2 *http.Request) {
		// Fix up the request URL
		req2.URL.Scheme = "https"
		req2.URL.Host = req2.Host
		wrapper.wrapped.ServeHTTP(resp2, req2)
	})
	go func() {
		err = http.Serve(listener, handler)
		if err != nil && err != io.EOF {
			log.Printf("Error serving mitm'ed connection: %s", err)
		}
	}()
	connIn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
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

func connBadGateway(connIn net.Conn, msg string) {
	log.Println(msg)
	connIn.Write([]byte(fmt.Sprintf("HTTP/1.1 502 Bad Gateway: %s", msg)))
	connIn.Close()
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
