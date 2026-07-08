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
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/bufferpool"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"net/netip"

	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

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
	pingStopMu sync.Mutex
	// DnsCacheSize, UdpSessionCacheSize, DnsTtl — размеры кэшей и TTL
	DnsCacheSize        int
	UdpSessionCacheSize int
	DnsTtl              time.Duration
}

// RoutineSpawner spawns a routine (e.g. socks5, tcp static routes) after the configuration is parsed
type RoutineSpawner interface {
	SpawnRoutine(ctx context.Context, vt *VirtualTun) error
}

type addressPort struct {
	address string
	port    uint16
}

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

// ---------- SpawnRoutine implementations ----------

// SpawnRoutine for Socks5Config
func (config *Socks5Config) SpawnRoutine(ctx context.Context, vt *VirtualTun) error {
	resolver := NewFixedResolver(vt.Tnet, vt.SystemDNS, vt.DnsTtl, vt.DnsCacheSize)
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
		defer func() {
			if r := recover(); r != nil {
				Log.Error("SOCKS5 listener goroutine panicked", "recover", r)
			}
		}()
		<-ctx.Done()
		listener.Close()
	}()

	if err := server.Serve(listener); err != nil {
		select {
		case <-ctx.Done():
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
		defer func() {
			if r := recover(); r != nil {
				Log.Error("TCPClient listener goroutine panicked", "recover", r)
			}
		}()
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
		defer func() {
			if r := recover(); r != nil {
				Log.Error("TCPServer listener goroutine panicked", "recover", r)
			}
		}()
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
	defer func() {
		if r := recover(); r != nil {
			Log.Error("connForward panicked", "recover", r)
		}
	}()
	defer func() { _ = from.Close() }()
	defer func() { _ = to.Close() }()

	_, err := io.Copy(to, from)
	if err != nil {
		Log.Error("Cannot forward traffic", "error", err)
	}
}

// tcpClientForward starts a new connection via wireguard and forward traffic from `conn`
func tcpClientForward(ctx context.Context, vt *VirtualTun, raddr *addressPort, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			Log.Error("tcpClientForward panicked", "recover", r)
		}
	}()
	defer conn.Close()

	target, err := vt.resolveToAddrPort(raddr)
	if err != nil {
		Log.Error("TCP Client Tunnel resolve error", "address", raddr.address, "error", err)
		return
	}

	tcpAddr := net.TCPAddrFromAddrPort(*target)
	sconn, err := vt.Tnet.DialTCP(tcpAddr)
	if err != nil {
		Log.Error("TCP Client Tunnel dial error", "target", target, "error", err)
		return
	}
	defer sconn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(IdleTimeout))
	_ = conn.SetWriteDeadline(time.Now().Add(IdleTimeout))
	_ = sconn.SetReadDeadline(time.Now().Add(IdleTimeout))
	_ = sconn.SetWriteDeadline(time.Now().Add(IdleTimeout))

	done := make(chan struct{}, 2)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				Log.Error("tcpClientForward copy goroutine 1 panicked", "recover", r)
			}
		}()
		_, _ = CopyWithPool(conn, sconn)
		done <- struct{}{}
	}()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				Log.Error("tcpClientForward copy goroutine 2 panicked", "recover", r)
			}
		}()
		_, _ = CopyWithPool(sconn, conn)
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}

// STDIOTcpForward starts a new connection via wireguard and forward traffic from `conn`
func STDIOTcpForward(ctx context.Context, vt *VirtualTun, raddr *addressPort) {
	defer func() {
		if r := recover(); r != nil {
			Log.Error("STDIOTcpForward panicked", "recover", r)
		}
	}()
	target, err := vt.resolveToAddrPort(raddr)
	if err != nil {
		Log.Error("Name resolution error", "address", raddr.address, "error", err)
		return
	}

	stdout, err := os.OpenFile("/dev/stdout", os.O_WRONLY, 0)
	if err != nil {
		Log.Error("Failed to open /dev/stdout", "error", err)
		return
	}
	defer stdout.Close()

	tcpAddr := net.TCPAddrFromAddrPort(*target)
	sconn, err := vt.Tnet.DialTCP(tcpAddr)
	if err != nil {
		Log.Error("TCP Client Tunnel dial error", "target", target, "tcpAddr", tcpAddr, "error", err)
		return
	}
	defer sconn.Close()

	_ = stdout.SetReadDeadline(time.Now().Add(IdleTimeout))
	_ = stdout.SetWriteDeadline(time.Now().Add(IdleTimeout))
	_ = sconn.SetReadDeadline(time.Now().Add(IdleTimeout))
	_ = sconn.SetWriteDeadline(time.Now().Add(IdleTimeout))

	go func() {
		defer func() {
			if r := recover(); r != nil {
				Log.Error("STDIOTcpForward copy goroutine 1 panicked", "recover", r)
			}
		}()
		connForward(os.Stdin, sconn)
	}()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				Log.Error("STDIOTcpForward copy goroutine 2 panicked", "recover", r)
			}
		}()
		connForward(sconn, stdout)
	}()

	<-ctx.Done()
}

// tcpServerForward starts a new connection locally and forward traffic from `conn`
func tcpServerForward(ctx context.Context, vt *VirtualTun, raddr *addressPort, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			Log.Error("tcpServerForward panicked", "recover", r)
		}
	}()
	defer conn.Close()

	target, err := vt.resolveToAddrPort(raddr)
	if err != nil {
		Log.Error("TCP Server Tunnel resolve error", "address", raddr.address, "error", err)
		return
	}

	tcpAddr := net.TCPAddrFromAddrPort(*target)
	sconn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		Log.Error("TCP Server Tunnel dial error", "target", target, "error", err)
		return
	}
	defer sconn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(IdleTimeout))
	_ = conn.SetWriteDeadline(time.Now().Add(IdleTimeout))
	_ = sconn.SetReadDeadline(time.Now().Add(IdleTimeout))
	_ = sconn.SetWriteDeadline(time.Now().Add(IdleTimeout))

	done := make(chan struct{}, 2)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				Log.Error("tcpServerForward copy goroutine 1 panicked", "recover", r)
			}
		}()
		_, _ = CopyWithPool(conn, sconn)
		done <- struct{}{}
	}()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				Log.Error("tcpServerForward copy goroutine 2 panicked", "recover", r)
			}
		}()
		_, _ = CopyWithPool(sconn, conn)
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}

// ---------- Health check and ping ----------

// ServeHTTP handles health and metrics requests
func (d VirtualTun) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			Log.Error("ServeHTTP panicked", "recover", r)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}()
	Log.Info("Health metric request", "path", r.URL.Path)
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
			Log.Error("Failed to get device metrics", "error", err)
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
			Log.Error("Failed to get device metrics", "error", err)
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
	defer func() {
		if r := recover(); r != nil {
			Log.Error("pingIPs panicked", "recover", r)
		}
	}()
	for _, addr := range d.Conf.CheckAlive {
		socket, err := d.Tnet.Dial("ping", addr.String())
		if err != nil {
			Log.Error("Failed to ping", "address", addr, "error", err)
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
			Log.Error("Failed to ping: invalid address", "address", addr)
			_ = socket.Close()
			continue
		}

		err = socket.SetReadDeadline(time.Now().Add(time.Duration(d.Conf.CheckAliveInterval) * time.Second))
		if err != nil {
			Log.Error("Failed to set read deadline", "address", addr, "error", err)
			_ = socket.Close()
			continue
		}

		_, err = socket.Write(icmpBytes)
		if err != nil {
			Log.Error("Failed to ping: write error", "address", addr, "error", err)
			_ = socket.Close()
			continue
		}

		addr := addr
		go func() {
			defer func() {
				if r := recover(); r != nil {
					Log.Error("pingIPs response goroutine panicked", "recover", r)
				}
			}()
			defer func() { _ = socket.Close() }()
			n, err := socket.Read(icmpBytes[:])
			if err != nil {
				Log.Error("Failed to read ping response", "address", addr, "error", err)
				return
			}

			replyPacket, err := icmp.ParseMessage(1, icmpBytes[:n])
			if err != nil {
				Log.Error("Failed to parse ping response", "address", addr, "error", err)
				return
			}

			if addr.Is4() {
				replyPing, ok := replyPacket.Body.(*icmp.Echo)
				if !ok {
					Log.Error("Failed to parse ping response: invalid reply type", "address", addr, "type", replyPacket.Type)
					return
				}
				if !bytes.Equal(replyPing.Data, requestPing.Data) || replyPing.Seq != requestPing.Seq {
					Log.Error("Failed to parse ping response: invalid ping reply", "address", addr, "reply", replyPing)
					return
				}
			}

			if addr.Is6() {
				replyPing, ok := replyPacket.Body.(*icmp.RawBody)
				if !ok {
					Log.Error("Failed to parse ping response: invalid reply type", "address", addr, "type", replyPacket.Type)
					return
				}

				if len(replyPing.Data) < 4 {
					Log.Error("Failed to parse ping response: packet too short", "address", addr)
					return
				}
				seq := binary.BigEndian.Uint16(replyPing.Data[2:4])
				pongBody := replyPing.Data[4:]
				if !bytes.Equal(pongBody, requestPing.Data) || int(seq) != requestPing.Seq {
					Log.Error("Failed to parse ping response: invalid ping reply", "address", addr, "reply", replyPing)
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

	go func() {
		defer func() {
			if r := recover(); r != nil {
				Log.Error("StartPingIPs goroutine panicked", "recover", r)
			}
		}()
		d.pingIPs()
		ticker := time.NewTicker(time.Duration(d.Conf.CheckAliveInterval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				d.pingIPs()
			}
		}
	}()
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
