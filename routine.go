package wireproxy

import (
	"bytes"
	"context"
	srand "crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/hashicorp/golang-lru/v2"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/bufferpool"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"net/netip"

	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

const idleTimeout = 5 * time.Minute // таймаут бездействия для TCP-соединений

// errorLogger is the logger to print error message
var errorLogger = log.New(os.Stderr, "ERROR: ", log.LstdFlags)

// CredentialValidator stores the authentication data of a socks5 proxy
type CredentialValidator struct {
	username string
	password string
}

// Valid checks username and password in constant time.
func (c CredentialValidator) Valid(username, password string) bool {
	u := subtle.ConstantTimeCompare([]byte(c.username), []byte(username))
	p := subtle.ConstantTimeCompare([]byte(c.password), []byte(password))
	return u&p == 1
}

// VirtualTun stores a reference to netstack network and DNS configuration
type VirtualTun struct {
	Tnet      *netstack.Net
	Dev       *device.Device
	SystemDNS bool
	Conf      *DeviceConfig
	// PingRecord — LRU-кэш для хранения времени последнего успешного ping-а (IP -> timestamp)
	PingRecord *lru.Cache[string, uint64]
	// pingStop allows to stop the background ping goroutine
	pingStop   chan struct{}
	pingStopMu sync.Mutex // защищает доступ к pingStop
	// DnsCacheSize определяет максимальное количество записей в DNS-кэше (LRU)
	DnsCacheSize int
	// UdpSessionCacheSize определяет максимальное количество UDP-сессий (LRU)
	UdpSessionCacheSize int
}

// RoutineSpawner spawns a routine (e.g. socks5, tcp static routes) after the configuration is parsed
// Теперь возвращает ошибку.
type RoutineSpawner interface {
	SpawnRoutine(ctx context.Context, vt *VirtualTun) error
}

type addressPort struct {
	address string
	port    uint16
}

// ---------- DNS resolver with LRU cache (limited memory growth) ----------

// fixedResolver implements socks5.NameResolver with a bounded LRU cache + TTL
type fixedResolver struct {
	tnet      *netstack.Net
	systemDNS bool
	cache     *expirable.LRU[string, net.IP]
	ttl       time.Duration
	mu        sync.RWMutex
}

// NewFixedResolver creates a new resolver with LRU cache and TTL expiration
func NewFixedResolver(tnet *netstack.Net, systemDNS bool, ttl time.Duration, cacheSize int) *fixedResolver {
	cache := expirable.NewLRU[string, net.IP](cacheSize, nil, ttl)
	return &fixedResolver{
		tnet:      tnet,
		systemDNS: systemDNS,
		cache:     cache,
		ttl:       ttl,
	}
}

// SetCacheSize изменяет размер кэша, создавая новый кэш с новым размером
// и копируя существующие записи из старого кэша (если они есть).
func (r *fixedResolver) SetCacheSize(newSize int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if newSize < 1 {
		newSize = 1
	}

	if r.cache == nil {
		r.cache = expirable.NewLRU[string, net.IP](newSize, nil, r.ttl)
		return
	}

	newCache := expirable.NewLRU[string, net.IP](newSize, nil, r.ttl)
	for _, key := range r.cache.Keys() {
		if val, ok := r.cache.Get(key); ok {
			newCache.Add(key, val)
		}
	}
	r.cache = newCache
}

// Resolve implements socks5.NameResolver
func (r *fixedResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	r.mu.RLock()
	ip, ok := r.cache.Get(name)
	r.mu.RUnlock()

	if ok {
		return ctx, ip, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if r.systemDNS {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", name)
		if err != nil || len(ips) == 0 {
			return ctx, nil, err
		}
		ip = ips[0]
	} else {
		addrs, err := r.tnet.LookupContextHost(ctx, name)
		if err != nil || len(addrs) == 0 {
			return ctx, nil, err
		}
		ip = net.ParseIP(addrs[0])
		if ip == nil {
			return ctx, nil, errors.New("failed to parse IP")
		}
	}

	r.mu.Lock()
	r.cache.Add(name, ip)
	r.mu.Unlock()
	return ctx, ip, nil
}

// Stop is a no-op for compatibility
func (r *fixedResolver) Stop() {
	// Nothing to do
}

// ---------- End of DNS resolver ----------

// LookupAddr lookups a hostname.
func (d VirtualTun) LookupAddr(ctx context.Context, name string) ([]string, error) {
	if d.SystemDNS {
		return net.DefaultResolver.LookupHost(ctx, name)
	}
	return d.Tnet.LookupContextHost(ctx, name)
}

// ResolveAddrWithContext resolves a hostname and returns an AddrPort.
func (d VirtualTun) ResolveAddrWithContext(ctx context.Context, name string) (*netip.Addr, error) {
	addrs, err := d.LookupAddr(ctx, name)
	if err != nil {
		return nil, err
	}

	size := len(addrs)
	if size == 0 {
		return nil, errors.New("no address found for: " + name)
	}

	rand.Shuffle(size, func(i, j int) {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	})

	var addr netip.Addr
	for _, saddr := range addrs {
		addr, err = netip.ParseAddr(saddr)
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil, err
	}

	return &addr, nil
}

// Resolve resolves a hostname and returns an IP.
func (d VirtualTun) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addr, err := d.ResolveAddrWithContext(ctx, name)
	if err != nil {
		return nil, nil, err
	}

	return ctx, addr.AsSlice(), nil
}

func parseAddressPort(endpoint string) (*addressPort, error) {
	name, sport, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return nil, &net.OpError{Op: "dial", Err: errors.New("port must be numeric")}
	}

	return &addressPort{address: name, port: uint16(port)}, nil
}

func (d VirtualTun) resolveToAddrPort(endpoint *addressPort) (*netip.AddrPort, error) {
	addr, err := d.ResolveAddrWithContext(context.Background(), endpoint.address)
	if err != nil {
		return nil, err
	}

	addrPort := netip.AddrPortFrom(*addr, endpoint.port)
	return &addrPort, nil
}

// ---------- SpawnRoutine implementations (теперь возвращают ошибку) ----------

// SpawnRoutine for Socks5Config
func (config *Socks5Config) SpawnRoutine(ctx context.Context, vt *VirtualTun) error {
	resolver := NewFixedResolver(vt.Tnet, vt.SystemDNS, 5*time.Minute, vt.DnsCacheSize)
	config.resolver = resolver

	var authMethods []socks5.Authenticator
	if username := config.Username; username != "" {
		authMethods = append(authMethods, socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{username: config.Password},
		})
	} else {
		authMethods = append(authMethods, socks5.NoAuthAuthenticator{})
	}

	options := []socks5.Option{
		socks5.WithDial(vt.Tnet.DialContext),
		socks5.WithResolver(resolver),
		socks5.WithAuthMethods(authMethods),
		socks5.WithBufferPool(bufferpool.NewPool(256 * 1024)),
	}

	server := socks5.NewServer(options...)

	listener, err := net.Listen("tcp", config.BindAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", config.BindAddress, err)
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	if err := server.Serve(listener); err != nil {
		select {
		case <-ctx.Done():
			// нормальное завершение
			return nil
		default:
			return fmt.Errorf("SOCKS5 server error: %w", err)
		}
	}
	return nil
}

// SpawnRoutine for HTTPConfig
func (config *HTTPConfig) SpawnRoutine(ctx context.Context, vt *VirtualTun) error {
	server := NewHTTPServer(config, vt.Tnet.Dial)
	if err := server.ListenAndServe(ctx, "tcp", config.BindAddress); err != nil {
		select {
		case <-ctx.Done():
			return nil
		default:
			return fmt.Errorf("HTTP server error: %w", err)
		}
	}
	return nil
}

// SpawnRoutine for TCPClientTunnelConfig
func (conf *TCPClientTunnelConfig) SpawnRoutine(ctx context.Context, vt *VirtualTun) error {
	raddr, err := parseAddressPort(conf.Target)
	if err != nil {
		return fmt.Errorf("parse target %s: %w", conf.Target, err)
	}

	server, err := net.ListenTCP("tcp", conf.BindAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", conf.BindAddress, err)
	}
	defer server.Close()

	go func() {
		<-ctx.Done()
		server.Close()
	}()

	for {
		conn, err := server.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("accept error: %w", err)
			}
		}
		go tcpClientForward(ctx, vt, raddr, conn)
	}
}

// SpawnRoutine for STDIOTunnelConfig
func (conf *STDIOTunnelConfig) SpawnRoutine(ctx context.Context, vt *VirtualTun) error {
	raddr, err := parseAddressPort(conf.Target)
	if err != nil {
		return fmt.Errorf("parse target %s: %w", conf.Target, err)
	}

	go STDIOTcpForward(ctx, vt, raddr)
	return nil
}

// SpawnRoutine for TCPServerTunnelConfig
func (conf *TCPServerTunnelConfig) SpawnRoutine(ctx context.Context, vt *VirtualTun) error {
	raddr, err := parseAddressPort(conf.Target)
	if err != nil {
		return fmt.Errorf("parse target %s: %w", conf.Target, err)
	}

	addr := &net.TCPAddr{Port: conf.ListenPort}
	server, err := vt.Tnet.ListenTCP(addr)
	if err != nil {
		return fmt.Errorf("listen on wireguard port %d: %w", conf.ListenPort, err)
	}
	defer server.Close()

	go func() {
		<-ctx.Done()
		server.Close()
	}()

	for {
		conn, err := server.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("accept error: %w", err)
			}
		}
		go tcpServerForward(ctx, vt, raddr, conn)
	}
}

// SpawnRoutine for UDPProxyTunnelConfig
func (conf *UDPProxyTunnelConfig) SpawnRoutine(ctx context.Context, vt *VirtualTun) error {
	return conf.SpawnUDPProxy(ctx, vt)
}

// connForward copy data from `from` to `to`
func connForward(from io.ReadWriteCloser, to io.ReadWriteCloser) {
	defer func() { _ = from.Close() }()
	defer func() { _ = to.Close() }()

	_, err := io.Copy(to, from)
	if err != nil {
		errorLogger.Printf("Cannot forward traffic: %s\n", err.Error())
	}
}

// tcpClientForward starts a new connection via wireguard and forward traffic from `conn`
func tcpClientForward(ctx context.Context, vt *VirtualTun, raddr *addressPort, conn net.Conn) {
	defer conn.Close()

	target, err := vt.resolveToAddrPort(raddr)
	if err != nil {
		errorLogger.Printf("TCP Client Tunnel resolve error for %s: %v\n", raddr.address, err)
		return
	}

	tcpAddr := net.TCPAddrFromAddrPort(*target)
	sconn, err := vt.Tnet.DialTCP(tcpAddr)
	if err != nil {
		errorLogger.Printf("TCP Client Tunnel to %s: %v\n", target, err)
		return
	}
	defer sconn.Close()

	// Устанавливаем таймаут на чтение для обоих соединений
	_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
	_ = sconn.SetReadDeadline(time.Now().Add(idleTimeout))

	done := make(chan struct{}, 2)
	go func() {
		_, _ = CopyWithPool(conn, sconn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = CopyWithPool(sconn, conn)
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-ctx.Done():
		// defer закроет соединения
	}
}

// STDIOTcpForward starts a new connection via wireguard and forward traffic from `conn`
func STDIOTcpForward(ctx context.Context, vt *VirtualTun, raddr *addressPort) {
	target, err := vt.resolveToAddrPort(raddr)
	if err != nil {
		errorLogger.Printf("Name resolution error for %s: %s\n", raddr.address, err.Error())
		return
	}

	stdout, err := os.OpenFile("/dev/stdout", os.O_WRONLY, 0)
	if err != nil {
		errorLogger.Printf("Failed to open /dev/stdout: %s\n", err.Error())
		return
	}
	defer stdout.Close()

	tcpAddr := net.TCPAddrFromAddrPort(*target)
	sconn, err := vt.Tnet.DialTCP(tcpAddr)
	if err != nil {
		errorLogger.Printf("TCP Client Tunnel to %s (%s): %s\n", target, tcpAddr, err.Error())
		return
	}
	defer sconn.Close()

	// Устанавливаем таймаут на чтение для STDIN и stdout (не критично, но можно)
	_ = os.Stdin.SetReadDeadline(time.Now().Add(idleTimeout))
	_ = stdout.SetReadDeadline(time.Now().Add(idleTimeout))
	_ = sconn.SetReadDeadline(time.Now().Add(idleTimeout))

	go connForward(os.Stdin, sconn)
	go connForward(sconn, stdout)

	<-ctx.Done()
}

// tcpServerForward starts a new connection locally and forward traffic from `conn`
func tcpServerForward(ctx context.Context, vt *VirtualTun, raddr *addressPort, conn net.Conn) {
	defer conn.Close()

	target, err := vt.resolveToAddrPort(raddr)
	if err != nil {
		errorLogger.Printf("TCP Server Tunnel resolve error for %s: %v\n", raddr.address, err)
		return
	}

	tcpAddr := net.TCPAddrFromAddrPort(*target)
	sconn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		errorLogger.Printf("TCP Server Tunnel to %s: %s\n", target, err.Error())
		return
	}
	defer sconn.Close()

	// Устанавливаем таймаут на чтение для обоих соединений
	_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
	_ = sconn.SetReadDeadline(time.Now().Add(idleTimeout))

	done := make(chan struct{}, 2)
	go func() {
		_, _ = CopyWithPool(conn, sconn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = CopyWithPool(sconn, conn)
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-ctx.Done():
		// defer закроет соединения
	}
}

// ---------- Health check and ping ----------

// ServeHTTP handles health and metrics requests
func (d VirtualTun) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Health metric request: %s\n", r.URL.Path)
	switch path.Clean(r.URL.Path) {
	case "/readyz":
		records := make(map[string]uint64)
		for _, key := range d.PingRecord.Keys() {
			if val, ok := d.PingRecord.Get(key); ok {
				records[key] = val
			}
		}
		body, err := json.Marshal(records)
		if err != nil {
			errorLogger.Printf("Failed to get device metrics: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		status := http.StatusOK
		for _, record := range records {
			lastPong := time.Unix(int64(record), 0)
			if time.Since(lastPong) > time.Duration(d.Conf.CheckAliveInterval+2)*time.Second {
				status = http.StatusServiceUnavailable
				break
			}
		}

		w.WriteHeader(status)
		_, _ = w.Write(body)
		_, _ = w.Write([]byte("\n"))
	case "/metrics":
		get, err := d.Dev.IpcGet()
		if err != nil {
			errorLogger.Printf("Failed to get device metrics: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var buf bytes.Buffer
		for _, peer := range strings.Split(get, "\n") {
			pair := strings.SplitN(peer, "=", 2)
			if len(pair) != 2 {
				buf.WriteString(peer)
				continue
			}
			if pair[0] == "private_key" || pair[0] == "preshared_key" {
				pair[1] = "REDACTED"
			}
			buf.WriteString(pair[0])
			buf.WriteString("=")
			buf.WriteString(pair[1])
			buf.WriteString("\n")
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d VirtualTun) pingIPs() {
	for _, addr := range d.Conf.CheckAlive {
		socket, err := d.Tnet.Dial("ping", addr.String())
		if err != nil {
			errorLogger.Printf("Failed to ping %s: %s\n", addr, err.Error())
			continue
		}

		data := make([]byte, 16)
		_, _ = srand.Read(data)

		requestPing := icmp.Echo{
			Seq:  rand.Intn(1 << 16),
			Data: data,
		}

		var icmpBytes []byte
		if addr.Is4() {
			icmpBytes, _ = (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
		} else if addr.Is6() {
			icmpBytes, _ = (&icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Code: 0, Body: &requestPing}).Marshal(nil)
		} else {
			errorLogger.Printf("Failed to ping %s: invalid address: %s\n", addr, addr.String())
			_ = socket.Close()
			continue
		}

		err = socket.SetReadDeadline(time.Now().Add(time.Duration(d.Conf.CheckAliveInterval) * time.Second))
		if err != nil {
			errorLogger.Printf("Failed to set read deadline for %s: %s\n", addr, err.Error())
			_ = socket.Close()
			continue
		}

		_, err = socket.Write(icmpBytes)
		if err != nil {
			errorLogger.Printf("Failed to ping %s: %s\n", addr, err.Error())
			_ = socket.Close()
			continue
		}

		addr := addr
		go func() {
			defer func() { _ = socket.Close() }()
			n, err := socket.Read(icmpBytes[:])
			if err != nil {
				errorLogger.Printf("Failed to read ping response from %s: %s\n", addr, err.Error())
				return
			}

			replyPacket, err := icmp.ParseMessage(1, icmpBytes[:n])
			if err != nil {
				errorLogger.Printf("Failed to parse ping response from %s: %s\n", addr, err.Error())
				return
			}

			if addr.Is4() {
				replyPing, ok := replyPacket.Body.(*icmp.Echo)
				if !ok {
					errorLogger.Printf("Failed to parse ping response from %s: invalid reply type: %s\n", addr, replyPacket.Type)
					return
				}
				if !bytes.Equal(replyPing.Data, requestPing.Data) || replyPing.Seq != requestPing.Seq {
					errorLogger.Printf("Failed to parse ping response from %s: invalid ping reply: %v\n", addr, replyPing)
					return
				}
			}

			if addr.Is6() {
				replyPing, ok := replyPacket.Body.(*icmp.RawBody)
				if !ok {
					errorLogger.Printf("Failed to parse ping response from %s: invalid reply type: %s\n", addr, replyPacket.Type)
					return
				}

				if len(replyPing.Data) < 4 {
					errorLogger.Printf("Failed to parse ping response from %s: packet too short\n", addr)
					return
				}
				seq := binary.BigEndian.Uint16(replyPing.Data[2:4])
				pongBody := replyPing.Data[4:]
				if !bytes.Equal(pongBody, requestPing.Data) || int(seq) != requestPing.Seq {
					errorLogger.Printf("Failed to parse ping response from %s: invalid ping reply: %v\n", addr, replyPing)
					return
				}
			}

			d.PingRecord.Add(addr.String(), uint64(time.Now().Unix()))
		}()
	}
}

// StartPingIPs starts a background goroutine that periodically pings all configured IPs.
func (d *VirtualTun) StartPingIPs() {
	d.pingStopMu.Lock()
	defer d.pingStopMu.Unlock()

	for _, addr := range d.Conf.CheckAlive {
		d.PingRecord.Add(addr.String(), 0)
	}

	if d.pingStop != nil {
		return
	}

	stopChan := make(chan struct{})
	d.pingStop = stopChan

	go func(stop <-chan struct{}) {
		d.pingIPs()
		ticker := time.NewTicker(time.Duration(d.Conf.CheckAliveInterval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				d.pingIPs()
			}
		}
	}(stopChan)
}

// StopPingIPs stops the background ping goroutine if it is running.
func (d *VirtualTun) StopPingIPs() {
	d.pingStopMu.Lock()
	defer d.pingStopMu.Unlock()

	if d.pingStop != nil {
		close(d.pingStop)
		d.pingStop = nil
	}
}
