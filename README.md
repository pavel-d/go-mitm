## go-mitm

go-mitm is a Go library that makes it easy to add MITM (Man in the Middle) capabilities to any Go-based HTTPS server, in particular intended for web proxies.

See [example.go](example/example.go) for an example on how to use it.

API documentation available on [godoc](https://godoc.org/github.com/oxtoacart/go-mitm/mitm).

gomitm requires a patched version of Go that supports dynamic certificate generation for SNI.  The source
code is available [here](https://code.google.com/r/oxtoacart-gomitm/).  Instructions for building Go from
source are [here](http://golang.org/doc/install/source).  Instead of cloning `https://code.google.com/p/go`,
clone `https://godoc.org/github.com/oxtoacart/gomitm`.