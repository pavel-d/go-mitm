// This example shows a proxy server that uses go-mitm to man-in-the-middle
// HTTPS connections opened with CONNECT requests

package mitm

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"code.google.com/p/go.net/html"
)

const (
	CONNECT   = "CONNECT"
	HTTP_ADDR = "127.0.0.1:8080"

	// The below are defined by package mitm already
	// ONE_WEEK  = 7 * 24 * time.Hour
	// TWO_WEEKS = ONE_WEEK * 2

	// PK_FILE   = "proxypk.pem"
	// CERT_FILE = "proxycert.pem"
)

var (
	proxy     *Proxy
	exampleWg sync.WaitGroup
)

func init() {
}

func Example() {
	var err error
	proxy, err = NewProxy(PK_FILE, CERT_FILE)
	if err != nil {
		log.Fatalf("Unable to initialize mitm proxy: %s", err)
	}
	exampleWg.Add(1)
	runHTTPServer()
	// Uncomment the below line to keep the server running
	//exampleWg.Wait()

	// Output:
}

func runHTTPServer() {
	server := &http.Server{
		Addr:         HTTP_ADDR,
		Handler:      http.HandlerFunc(handleRequest),
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

func handleRequest(resp http.ResponseWriter, req *http.Request) {
	if req.Method == CONNECT {
		proxy.Intercept(resp, req)
	} else {
		reverseProxy(resp, req)
	}
}

func reverseProxy(resp http.ResponseWriter, req *http.Request) {
	rp := httputil.ReverseProxy{
		Director: func(req *http.Request) {
		},
	}
	rp.ServeHTTP(resp, req)
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
