// This example shows a proxy server that uses go-mitm to man-in-the-middle
// HTTPS connections opened with CONNECT requests

package mitm

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"code.google.com/p/go.net/html"
	"github.com/getlantern/go-mitm/mitm"
)

const (
	CONNECT   = "CONNECT"
	ONE_WEEK  = 7 * 24 * time.Hour
	TWO_WEEKS = ONE_WEEK * 2

	PK_FILE   = "proxypk.pem"
	CERT_FILE = "proxycert.pem"

	HTTP_ADDR = "127.0.0.1:8080"
)

var (
	proxy *mitm.Proxy
)

func init() {
}

func Example() {
	var err error
	proxy, err = mitm.NewProxy(PK_FILE, CERT_FILE)
	if err != nil {
		log.Fatalf("Unable to initialize mitm proxy: %s", err)
	}
	httpFinished := runHTTPServer()
	<-httpFinished
}

func runHTTPServer() (finished chan bool) {
	finished = make(chan bool)

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
		finished <- true
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

func addProxyingInfo(body io.Reader, out io.Writer) {
	z := html.NewTokenizer(body)
	lookingForBody := true
	for lookingForBody == true {
		tt := z.Next()
		fmt.Println(tt.String())
		if tt == html.ErrorToken {
			return
		}
		if tt == html.StartTagToken {
			out.Write([]byte("<div style='background-color: red; font-weight: bold; height: 30px;'><a href='javascript:void(0);'>Click Here to Proxy with Lantern</a>"))
			lookingForBody = false
		}
		out.Write([]byte(z.Token().String()))
	}
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
