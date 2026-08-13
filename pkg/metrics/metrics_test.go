package metrics

import "testing"

func TestStartMetricsServerHasTimeouts(t *testing.T) {
	server := StartMetricsServer("127.0.0.1:0")
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout <= 0 || server.IdleTimeout <= 0 {
		t.Fatalf("metrics server must set all timeouts, got %+v", server)
	}
	if server.MaxHeaderBytes <= 0 {
		t.Fatal("metrics server must bound header size")
	}
}
