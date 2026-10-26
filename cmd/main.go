package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prefeitura-rio/app-ext-authz/internal/config"
	"github.com/prefeitura-rio/app-ext-authz/internal/service"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	recaptchaTokenHeader = "x-recaptcha-token"
	resultHeader         = "x-ext-authz-check-result"
	receivedHeader       = "x-ext-authz-check-received"
	resultAllowed        = "allowed"
	resultDenied         = "denied"
)

var (
	httpPort = flag.String("http", "8000", "HTTP server port")
	grpcPort = flag.String("grpc", "9000", "gRPC server port")
	denyBody = fmt.Sprintf("denied by ext_authz for missing header `%s`", recaptchaTokenHeader)
)

// ExtAuthzServer implements the ext_authz v3 gRPC and HTTP check request API.
type ExtAuthzServer struct {
	grpcServer *grpc.Server
	httpServer *http.Server
	service    *service.Service
	// For test only
	httpPort chan int
	grpcPort chan int
}

func (s *ExtAuthzServer) logRequest(allow string, request *authv3.CheckRequest) {
	httpAttrs := request.GetAttributes().GetRequest().GetHttp()
	log.Printf("[gRPCv3][%s]: %s%s, attributes: %v\n", allow, httpAttrs.GetHost(),
		httpAttrs.GetPath(),
		request.GetAttributes())
}

func (s *ExtAuthzServer) allow(request *authv3.CheckRequest) *authv3.CheckResponse {
	s.logRequest("allowed", request)
	return &authv3.CheckResponse{
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   resultHeader,
							Value: resultAllowed,
						},
					},
					{
						Header: &corev3.HeaderValue{
							Key:   receivedHeader,
							Value: returnIfNotTooLong(request.GetAttributes().String()),
						},
					},
				},
			},
		},
		Status: &status.Status{Code: int32(codes.OK)},
	}
}

func (s *ExtAuthzServer) deny(request *authv3.CheckRequest) *authv3.CheckResponse {
	s.logRequest("denied", request)
	// No debug headers are returned to the client on denied responses; the
	// decision details are only kept in the server logs (see logRequest).
	return &authv3.CheckResponse{
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Body:   denyBody,
			},
		},
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
	}
}

// logDenyDetails logs, server-side, the reCAPTCHA decision details that used to
// be exposed to clients through X-Recaptcha-* response headers.
func (s *ExtAuthzServer) logDenyDetails(authResponse *service.AuthorizationResponse) {
	log.Printf("[gRPCv3][denied][details]: %s", denyDetails(authResponse, s.circuitBreakerState))
}

func (s *ExtAuthzServer) circuitBreakerState() string {
	if s.service == nil {
		return "unknown"
	}
	return s.service.GetCircuitBreakerState()
}

// denyDetails renders the decision details of a denied request for logging.
func denyDetails(authResponse *service.AuthorizationResponse, cbState func() string) string {
	health := "healthy"
	cb := ""
	if authResponse.Status == "degraded" || authResponse.Status == "circuit_breaker_open" {
		health = "degraded"
		cb = cbState()
	}
	return fmt.Sprintf("%s=%s x-recaptcha-status=%q x-recaptcha-score=%q x-recaptcha-cache=%q x-recaptcha-service-health=%q x-recaptcha-circuit-breaker-state=%q",
		resultHeader, resultDenied, authResponse.Status, authResponse.Score, authResponse.Cache, health, cb)
}

func (s *ExtAuthzServer) denyWithDetails(request *authv3.CheckRequest, authResponse *service.AuthorizationResponse) *authv3.CheckResponse {
	s.logRequest("denied", request)
	
	// Debug details are logged server-side only and never returned to the client.
	s.logDenyDetails(authResponse)

	// Provide more accurate error message based on status
	var errorMessage string
	switch authResponse.Status {
	case "malformed":
		errorMessage = "denied by ext_authz: invalid reCAPTCHA token format"
	case "timeout":
		errorMessage = "denied by ext_authz: reCAPTCHA validation timeout"
	case "degraded":
		errorMessage = "denied by ext_authz: service degraded, validation failed"
	case "circuit_breaker_open":
		errorMessage = "denied by ext_authz: service temporarily unavailable"
	default:
		errorMessage = fmt.Sprintf("denied by ext_authz: %s", authResponse.Status)
	}
	
	return &authv3.CheckResponse{
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Body:   errorMessage,
			},
		},
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
	}
}

// Check implements gRPC v3 check request.
func (s *ExtAuthzServer) Check(ctx context.Context, request *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	attrs := request.GetAttributes()
	httpAttrs := attrs.GetRequest().GetHttp()

	// Allow OPTIONS requests (CORS preflight) without requiring reCAPTCHA token
	if httpAttrs.GetMethod() == "OPTIONS" {
		return s.allow(request), nil
	}

	// Extract reCAPTCHA token from headers
	token := ""
	if headers := httpAttrs.GetHeaders(); headers != nil {
		if tokenValue, exists := headers[recaptchaTokenHeader]; exists {
			token = tokenValue
		}
	}

	// If no token provided, deny the request
	if token == "" {
		return s.deny(request), nil
	}

	// Create authorization request
	authReq := &service.AuthorizationRequest{
		Token: token,
	}

	// Call our service to validate the token
	response, err := s.service.Authorize(ctx, authReq)
	if err != nil {
		log.Printf("Authorization error: %v", err)
		return s.deny(request), nil
	}

	// Return allow/deny based on service response
	if response.Allowed {
		return s.allow(request), nil
	}

	// Create a custom deny response with detailed information
	return s.denyWithDetails(request, response), nil
}

// ServeHTTP implements the HTTP check request.
func (s *ExtAuthzServer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		log.Printf("[HTTP] read body failed: %v", err)
	}

	l := fmt.Sprintf("%s %s%s, headers: %v, body: [%s]\n", request.Method, request.Host, request.URL, request.Header, returnIfNotTooLong(string(body)))

	// Allow OPTIONS requests (CORS preflight) without requiring reCAPTCHA token
	if request.Method == "OPTIONS" {
		log.Printf("[HTTP][allowed]: %s", l)
		response.Header().Set(resultHeader, resultAllowed)
		response.Header().Set(receivedHeader, l)
		response.WriteHeader(http.StatusOK)
		return
	}

	// Extract reCAPTCHA token from header
	token := request.Header.Get(recaptchaTokenHeader)
	if token == "" {
		log.Printf("[HTTP][denied]: %s=%s %s=%s", resultHeader, resultDenied, receivedHeader, l)
		response.WriteHeader(http.StatusForbidden)
		_, _ = response.Write([]byte(denyBody))
		return
	}

	// Create authorization request
	authReq := &service.AuthorizationRequest{
		Token: token,
	}

	// Call our service to validate the token
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	authResponse, err := s.service.Authorize(ctx, authReq)
	if err != nil {
		log.Printf("[HTTP] authorization error: %v", err)
		log.Printf("[HTTP][denied]: %s=%s %s=%s", resultHeader, resultDenied, receivedHeader, l)
		response.WriteHeader(http.StatusForbidden)
		_, _ = response.Write([]byte(denyBody))
		return
	}

	// Return response based on authorization result
	if authResponse.Allowed {
		log.Printf("[HTTP][allowed]: %s", l)
		response.Header().Set(resultHeader, resultAllowed)
		response.Header().Set(receivedHeader, l)
		response.WriteHeader(http.StatusOK)
	} else {
		// Debug details are logged server-side only, never sent to the client.
		log.Printf("[HTTP][denied]: %s %s=%s", denyDetails(authResponse, s.circuitBreakerState), receivedHeader, l)

		// Provide more accurate error message based on status
		var errorMessage string
		switch authResponse.Status {
		case "malformed":
			errorMessage = "denied by ext_authz: invalid reCAPTCHA token format"
		case "timeout":
			errorMessage = "denied by ext_authz: reCAPTCHA validation timeout"
		case "degraded":
			errorMessage = "denied by ext_authz: service degraded, validation failed"
		case "circuit_breaker_open":
			errorMessage = "denied by ext_authz: service temporarily unavailable"
		default:
			errorMessage = fmt.Sprintf("denied by ext_authz: %s", authResponse.Status)
		}
		
		response.WriteHeader(http.StatusForbidden)
		_, _ = response.Write([]byte(errorMessage))
	}
}

func (s *ExtAuthzServer) startGRPC(address string, wg *sync.WaitGroup) {
	defer func() {
		wg.Done()
		log.Printf("Stopped gRPC server")
	}()

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to start gRPC server: %v", err)
		return
	}
	// Store the port for test only.
	s.grpcPort <- listener.Addr().(*net.TCPAddr).Port

	s.grpcServer = grpc.NewServer()
	authv3.RegisterAuthorizationServer(s.grpcServer, s)

	log.Printf("Starting gRPC server at %s", listener.Addr())
	if err := s.grpcServer.Serve(listener); err != nil {
		log.Fatalf("Failed to serve gRPC server: %v", err)
		return
	}
}

func (s *ExtAuthzServer) startHTTP(address string, wg *sync.WaitGroup) {
	defer func() {
		wg.Done()
		log.Printf("Stopped HTTP server")
	}()

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to create HTTP server: %v", err)
	}
	// Store the port for test only.
	s.httpPort <- listener.Addr().(*net.TCPAddr).Port
	s.httpServer = &http.Server{Handler: s}

	log.Printf("Starting HTTP server at %s", listener.Addr())
	if err := s.httpServer.Serve(listener); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}

func (s *ExtAuthzServer) run(httpAddr, grpcAddr string) {
	var wg sync.WaitGroup
	wg.Add(2)
	go s.startHTTP(httpAddr, &wg)
	go s.startGRPC(grpcAddr, &wg)
	wg.Wait()
}

func (s *ExtAuthzServer) stop() {
	if s.grpcServer != nil {
		s.grpcServer.Stop()
		log.Printf("GRPC server stopped")
	}
	if s.httpServer != nil {
		log.Printf("HTTP server stopped: %v", s.httpServer.Close())
	}
	// Shutdown service (which handles telemetry)
	if s.service != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.service.Shutdown(ctx); err != nil {
			log.Printf("Service shutdown error: %v", err)
		}
	}
}

func NewExtAuthzServer() (*ExtAuthzServer, error) {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Create service (this will handle telemetry internally)
	svc, err := service.NewService(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create service: %w", err)
	}

	return &ExtAuthzServer{
		service:   svc,
		httpPort:  make(chan int, 1),
		grpcPort:  make(chan int, 1),
	}, nil
}

func main() {
	flag.Parse()

	s, err := NewExtAuthzServer()
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	go s.run(fmt.Sprintf(":%s", *httpPort), fmt.Sprintf(":%s", *grpcPort))
	defer s.stop()

	// Wait for the process to be shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}

func returnIfNotTooLong(body string) string {
	// Maximum size of a header accepted by Envoy is 60KiB, so when the request body is bigger than 60KB,
	// we don't return it in a response header to avoid rejecting it by Envoy and returning 431 to the client
	if len(body) > 60000 {
		return "<too-long>"
	}
	return body
} 