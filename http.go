package wireproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const proxyAuthHeaderKey = "Proxy-Authorization"

type HTTPServer struct {
	config       *HTTPConfig
	auth         CredentialValidator
	authRequired bool
	httpClient   *http.Client
}

func NewHTTPServer(config *HTTPConfig, dial func(network, address string) (net.Conn, error)) *HTTPServer {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dial(network, addr)
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &HTTPServer{
		config:       config,
		auth:         CredentialValidator{config.Username, config.Password},
		authRequired: config.Username != "" || config.Password != "",
		httpClient:   client,
	}
}

func responseWith(req *http.Request, statusCode int) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       http.NoBody,
		Request:    req,
	}
}

func (s *HTTPServer) authenticate(req *http.Request) (int, error) {
	if !s.authRequired {
		return 0, nil
	}
	auth := req.Header.Get(proxyAuthHeaderKey)
	if auth == "" {
		return http.StatusProxyAuthRequired, fmt.Errorf("%s", http.StatusText(http.StatusProxyAuthRequired))
	}
	enc := strings.TrimPrefix(auth, "Basic ")
	str, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return http.StatusNotAcceptable, fmt.Errorf("decode username and password failed: %w", err)
	}
	pairs := bytes.SplitN(str, []byte(":"), 2)
	if len(pairs) != 2 {
		return http.StatusLengthRequired, fmt.Errorf("username and password format invalid")
	}
	if s.auth.Valid(string(pairs[0]), string(pairs[1])) {
		return 0, nil
	}
	return http.StatusUnauthorized, fmt.Errorf("username and password not matching")
}

func (s *HTTPServer) handleConn(req *http.Request, conn net.Conn) (peer net.Conn, err error) {
	addr := req.Host
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(addr, "443")
	}
	peer, err = s.httpClient.Transport.(*http.Transport).DialContext(req.Context(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}
	_, err = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		_ = peer.Close()
		return nil, fmt.Errorf("write response failed: %w", err)
	}
	return peer, nil
}

func (s *HTTPServer) handle(req *http.Request, conn net.Conn) error {
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authenticate")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http client do failed: %w", err)
	}
	defer resp.Body.Close()
	resp.Header.Del("Proxy-Connection")
	resp.Header.Del("Proxy-Authenticate")
	if err := resp.Write(conn); err != nil {
		return fmt.Errorf("write response failed: %w", err)
	}
	return nil
}

func (s *HTTPServer) serve(conn net.Conn) {
	defer conn.Close()
	rd := bufio.NewReader(conn)
	req, err := http.ReadRequest(rd)
	if err != nil {
		log.Printf("read request failed: %v", err)
		return
	}
	code, err := s.authenticate(req)
	if err != nil {
		resp := responseWith(req, code)
		if code == http.StatusProxyAuthRequired {
			resp.Header.Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
		}
		_ = resp.Write(conn)
		log.Println(err)
		return
	}
	switch req.Method {
	case http.MethodConnect:
		peer, err := s.handleConn(req, conn)
		if err != nil {
			log.Printf("CONNECT failed: %v", err)
			if peer != nil {
				_ = peer.Close()
			}
			return
		}
		defer peer.Close()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = CopyWithPool(conn, peer)
		}()
		go func() {
			defer wg.Done()
			_, _ = CopyWithPool(peer, conn)
		}()
		wg.Wait()
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodHead, http.MethodPatch, http.MethodOptions:
		err = s.handle(req, conn)
		if err != nil {
			log.Printf("HTTP request failed: %v", err)
		}
	default:
		_ = responseWith(req, http.StatusMethodNotAllowed).Write(conn)
		log.Printf("unsupported method: %s", req.Method)
	}
}

func (s *HTTPServer) ListenAndServe(network, addr string) error {
	listener, err := net.Listen(network, addr)
	if err != nil {
		return fmt.Errorf("listen failed: %w", err)
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept failed: %w", err)
		}
		go s.serve(conn)
	}
}package wireproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const proxyAuthHeaderKey = "Proxy-Authorization"

type HTTPServer struct {
	config     *HTTPConfig
	auth       CredentialValidator
	authRequired bool
	httpClient *http.Client // клиент с пулом соединений для обычных HTTP-запросов
}

// NewHTTPServer создаёт HTTPServer с настроенным HTTP-клиентом и пулом соединений.
func NewHTTPServer(config *HTTPConfig, dial func(network, address string) (net.Conn, error)) *HTTPServer {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dial(network, addr)
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		// Не следуем перенаправлениям (прокси не должен этого делать)
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &HTTPServer{
		config:       config,
		auth:         CredentialValidator{config.Username, config.Password},
		authRequired: config.Username != "" || config.Password != "",
		httpClient:   client,
	}
}

// responseWith создаёт HTTP-ответ с заданным статус-кодом.
func responseWith(req *http.Request, statusCode int) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       http.NoBody,
		Request:    req,
	}
}

func (s *HTTPServer) authenticate(req *http.Request) (int, error) {
	if !s.authRequired {
		return 0, nil
	}

	auth := req.Header.Get(proxyAuthHeaderKey)
	if auth == "" {
		return http.StatusProxyAuthRequired, fmt.Errorf("%s", http.StatusText(http.StatusProxyAuthRequired))
	}

	enc := strings.TrimPrefix(auth, "Basic ")
	str, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return http.StatusNotAcceptable, fmt.Errorf("decode username and password failed: %w", err)
	}
	pairs := bytes.SplitN(str, []byte(":"), 2)
	if len(pairs) != 2 {
		return http.StatusLengthRequired, fmt.Errorf("username and password format invalid")
	}
	if s.auth.Valid(string(pairs[0]), string(pairs[1])) {
		return 0, nil
	}
	return http.StatusUnauthorized, fmt.Errorf("username and password not matching")
}

// handleConn обрабатывает CONNECT-запросы (установка туннеля)
func (s *HTTPServer) handleConn(req *http.Request, conn net.Conn) (peer net.Conn, err error) {
	addr := req.Host
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(addr, "443")
	}

	peer, err = s.httpClient.Transport.(*http.Transport).DialContext(req.Context(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	_, err = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		_ = peer.Close()
		return nil, fmt.Errorf("write response failed: %w", err)
	}

	return peer, nil
}

// handle обрабатывает обычные HTTP-запросы (GET, POST и т.д.) через клиент с пулом соединений.
func (s *HTTPServer) handle(req *http.Request, conn net.Conn) error {
	// Удаляем заголовки, специфичные для прокси
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authenticate")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http client do failed: %w", err)
	}
	defer resp.Body.Close()

	// Удаляем лишние заголовки прокси
	resp.Header.Del("Proxy-Connection")
	resp.Header.Del("Proxy-Authenticate")

	// Записываем ответ клиенту
	if err := resp.Write(conn); err != nil {
		return fmt.Errorf("write response failed: %w", err)
	}
	return nil
}

// serve обрабатывает одно клиентское соединение.
func (s *HTTPServer) serve(conn net.Conn) {
	defer conn.Close()

	rd := bufio.NewReader(conn)
	req, err := http.ReadRequest(rd)
	if err != nil {
		log.Printf("read request failed: %v", err)
		return
	}

	code, err := s.authenticate(req)
	if err != nil {
		resp := responseWith(req, code)
		if code == http.StatusProxyAuthRequired {
			resp.Header.Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
		}
		_ = resp.Write(conn)
		log.Println(err)
		return
	}

	switch req.Method {
	case http.MethodConnect:
		peer, err := s.handleConn(req, conn)
		if err != nil {
			log.Printf("CONNECT failed: %v", err)
			if peer != nil {
				_ = peer.Close()
			}
			return
		}
		defer peer.Close()

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = CopyWithPool(conn, peer)
		}()
		go func() {
			defer wg.Done()
			_, _ = CopyWithPool(peer, conn)
		}()
		wg.Wait()

	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodHead, http.MethodPatch, http.MethodOptions:
		err = s.handle(req, conn)
		if err != nil {
			log.Printf("HTTP request failed: %v", err)
		}
	default:
		_ = responseWith(req, http.StatusMethodNotAllowed).Write(conn)
		log.Printf("unsupported method: %s", req.Method)
	}
}

// ListenAndServe запускает TCP-сервер.
func (s *HTTPServer) ListenAndServe(network, addr string) error {
	listener, err := net.Listen(network, addr)
	if err != nil {
		return fmt.Errorf("listen failed: %w", err)
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept failed: %w", err)
		}
		go s.serve(conn)
	}
}
