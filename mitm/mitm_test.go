package mitm

import (
	"crypto/tls"
	"testing"
)

// Make sure our pointer copying technique actually works.
func TestMakeTLS(t *testing.T) {

	template := &tls.Config{ServerName: "test"}

	made := makeConfig(template)

	if made.ServerName != template.ServerName {
		t.Error("Config not a copy")
	}

	template.ServerName = "different"

	if made.ServerName == template.ServerName {
		t.Error("Copy not a copy")
	}
}
