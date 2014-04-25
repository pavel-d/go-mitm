// This example shows a proxy server that uses go-mitm to man-in-the-middle
// HTTPS connections opened with CONNECT requests

package mitm

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"
)

const (
	HTTP_ADDR         = "127.0.0.1:8080"
	SESSIONS_TO_CACHE = 10000
)

var (
	exampleWg sync.WaitGroup
)

func init() {

}

func Example() {
	exampleWg.Add(1)
	runHTTPServer()
	// Uncomment the below line to keep the server running
	// exampleWg.Wait()

	// Output:
}

func runHTTPServer() {
	cryptoConfig := &CryptoConfig{
		PKFile:   "proxypk.pem",
		CertFile: "proxycert.pem",
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			log.Printf("Processing request to: %s", req.URL)
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// Use a TLS session cache to minimize TLS connection establishment
				// Requires Go 1.3+
				ClientSessionCache: tls.NewLRUClientSessionCache(SESSIONS_TO_CACHE),
			},
		},
	}

	handler, err := Wrap(rp, cryptoConfig)
	if err != nil {
		log.Fatalf("Unable to wrap reverse proxy: %s", err)
	}

	server := &http.Server{
		Addr:         HTTP_ADDR,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("About to start HTTP proxy at %s", HTTP_ADDR)
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Unable to start HTTP proxy: %s", err)
		}
		exampleWg.Done()
	}()

	return
}

// The below are defined by package mitm already
// func respondBadGateway(resp http.ResponseWriter, req *http.Request, msg string) {
// 	resp.WriteHeader(502)
// 	resp.Write([]byte(fmt.Sprintf("Bad Gateway: %s - %s", req.URL, msg)))
// }

// func pipe(connIn net.Conn, connOut net.Conn) {
// 	go func() {
// 		defer connIn.Close()
// 		io.Copy(connOut, connIn)
// 	}()
// 	go func() {
// 		defer connOut.Close()
// 		io.Copy(connIn, connOut)
// 	}()
// }

func unused() {}
