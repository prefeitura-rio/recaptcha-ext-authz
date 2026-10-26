package main

import (
	"bytes"
	"log"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/prefeitura-rio/app-ext-authz/internal/service"
)

func testRequest() *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Host:   "services.example.test",
					Method: "GET",
					Path:   "/secret/internal/path",
					Headers: map[string]string{
						"host": "services.example.test",
					},
				},
			},
		},
	}
}

func headerKeys(hs []*corev3.HeaderValueOption) map[string]string {
	out := map[string]string{}
	for _, h := range hs {
		out[strings.ToLower(h.GetHeader().GetKey())] = h.GetHeader().GetValue()
	}
	return out
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })
	return &buf
}

func assertNoDebugHeaders(t *testing.T, resp *authv3.CheckResponse) {
	t.Helper()
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatalf("expected a denied response, got %T", resp.GetHttpResponse())
	}
	for k := range headerKeys(denied.GetHeaders()) {
		if strings.HasPrefix(k, "x-recaptcha-") || strings.HasPrefix(k, "x-ext-authz-check-") {
			t.Errorf("denied response leaks debug header %q", k)
		}
	}
	if len(denied.GetHeaders()) != 0 {
		t.Errorf("expected no headers on denied response, got %d", len(denied.GetHeaders()))
	}
}

func TestDenyWithDetailsDoesNotLeakHeadersButLogsThem(t *testing.T) {
	for _, status := range []string{"malformed", "timeout", "degraded", "circuit_breaker_open"} {
		t.Run(status, func(t *testing.T) {
			buf := captureLog(t)
			s := &ExtAuthzServer{}
			resp := s.denyWithDetails(testRequest(), &service.AuthorizationResponse{
				Status: status,
				Score:  "0.1",
				Cache:  "hit",
			})
			assertNoDebugHeaders(t, resp)
			if resp.GetDeniedResponse().GetStatus().GetCode() != 403 {
				t.Errorf("status changed: %v", resp.GetDeniedResponse().GetStatus())
			}
			if !strings.HasPrefix(resp.GetDeniedResponse().GetBody(), "denied by ext_authz: ") {
				t.Errorf("unexpected body %q", resp.GetDeniedResponse().GetBody())
			}
			logs := buf.String()
			for _, want := range []string{
				"x-ext-authz-check-result=denied",
				"x-recaptcha-status=\"" + status + "\"",
				"x-recaptcha-score=\"0.1\"",
				"x-recaptcha-cache=\"hit\"",
				"x-recaptcha-service-health=",
				"x-recaptcha-circuit-breaker-state=",
				"/secret/internal/path", // request attributes (received) still logged
			} {
				if !strings.Contains(logs, want) {
					t.Errorf("log missing %q; got:\n%s", want, logs)
				}
			}
		})
	}
}

func TestDenyDoesNotLeakHeaders(t *testing.T) {
	buf := captureLog(t)
	s := &ExtAuthzServer{}
	resp := s.deny(testRequest())
	assertNoDebugHeaders(t, resp)
	if resp.GetDeniedResponse().GetBody() != denyBody {
		t.Errorf("body changed: %q", resp.GetDeniedResponse().GetBody())
	}
	if !strings.Contains(buf.String(), "[denied]") || !strings.Contains(buf.String(), "/secret/internal/path") {
		t.Errorf("deny log missing info: %s", buf.String())
	}
}

func TestAllowKeepsUpstreamHeaders(t *testing.T) {
	captureLog(t)
	s := &ExtAuthzServer{}
	resp := s.allow(testRequest())
	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatalf("expected ok response")
	}
	got := headerKeys(ok.GetHeaders())
	if got[resultHeader] != resultAllowed {
		t.Errorf("allowed header %s = %q, want %q", resultHeader, got[resultHeader], resultAllowed)
	}
	if _, found := got[receivedHeader]; !found {
		t.Errorf("allowed response lost %s", receivedHeader)
	}
}
