package wireproxy

import (
	"bytes"
	"context"
	srand "crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
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
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/bufferpool"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"net/netip"

	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

// ---------- Глобальные оптимизации ----------

var defaultDialer = &net.Dialer{
	Timeout:   DialTimeout,
	KeepAlive: 30 * time.Second,
}

var socksPool = bufferpool.NewPool(64 * 1024)

// Семафор для ограничения количества одновременно устанавливаемых TCP-соединений
var tcpSemaphore = make(chan struct{}, 100) // максимум 100 соединений

// Пул для ICMP-буферов
var icmpBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 16)
	},
}

// ---------- timeoutConn обёртка с таймаутами ----------

// timeoutConn оборачивает net.Conn и устанавливает таймауты на чтение/запись
type timeoutConn struct {
	net.Conn
	idle time.Duration
}

func (c *timeoutConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(p)
}

func (c *timeoutConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(p)
}

// dialWithTimeout создаёт соединение через vt.Tnet.DialContext и оборачивает его в timeoutConn
func dialWithTimeout(ctx context.Context, network, addr string, vt *VirtualTun) (net.Conn, error) {
	conn, err := vt.Tnet.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &timeoutConn{
		Conn: conn,
		idle: IdleTimeout, // используем глобальную константу
	}, nil
}

// ---------- CredentialValidator ----------

type CredentialValidator struct {
	username string
	password string
}

func (c CredentialValidator) Valid(username, password string) bool {
	u := subtle.ConstantTimeCompare([]byte(c.username), []byte(username))
	p := subtle.ConstantTimeCompare([]byte(c.password), []byte(password))
	return u&p == 1
}

// ---------- VirtualTun ----------

type VirtualTun struct {
	Tnet      *netstack.Net
	Dev       *device.Device
	SystemDNS bool
	Conf      *DeviceConfig

	// PingRecord — expirable.LRU с автоматическим удалением записей по TTL
	PingRecord *expirable.LRU[string, uint64]

	// pingStop для остановки фоновой горутины
	pingStop   chan struct{}
	pingStopMu sync.Mutex

	// Размеры кэшей
	DnsCacheSize        int
	UdpSessionCacheSize int
	DnsTtl              time.Duration

	// Worker pool для ICMP-пингов
	pingJobs    chan pingJob
	pingWorkers sync.WaitGroup
	pingCtx     context.Context
	pingCancel  context.CancelFunc
}

type pingJob struct {
	addr        netip.Addr
	requestPing icmp.Echo
}

// ---------- RoutineSpawner ----------

type RoutineSpawner interface {
	SpawnRoutine(ctx context.Context, vt *VirtualTun) error
}

type addressPort struct {
	address string
	port    uint16
}

// ---------- Вспомогательные функции ----------

func (d VirtualTun) LookupAddr(ctx context.Context, name string) ([]string, error) {
	if d.SystemDNS {
		return net.DefaultResolver.LookupHost(ctx, name)
	}
	return d.Tnet.LookupContextHost(ctx, name)
}

func (d VirtualTun) ResolveAddrWithContext(ctx context.Context, name string) (*netip.Addr, error) {
	addrs, err := d.LookupAddr(ctx, name)
	if err != nil {
		return nil, err
	}
	size := len(addrs)
	if size == 0 {
		return nil, errors.New("no address found for: " + name)
	}
	// Локальный генератор для перемешивания
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(size, func(i, j int) {
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

func (d VirtualTun) resolveToAddrPort(ctx context.Context, endpoint *addressPort) (*netip.AddrPort, error) {
	addr, err := d.ResolveAddrWithContext(ctx, endpoint.address)
	if err != nil {
		return nil, err
	}
	addrPort := netip.AddrPortFrom(*addr, endpoint.port)
	return &addrPort, nil
}

// ---------- SpawnRoutine implementations ----------

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

	// Обёртка для Dial с таймаутами
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialWithTimeout(ctx, network, addr, vt)
	}

	options := []socks5.Option{
		socks5.WithDial(dial), // используем обёртку вместо vt.Tnet.DialContext
		socks5.WithResolver(resolver),
		socks5.WithAuthMethods(authMethods),
		socks5.WithBufferPool(socksPool),
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		server := socks5.NewServer(options...)
		var listener net.Listener
		var err error
		for i := 0; i < 5; i++ {
			listener, err = net.Listen("tcp", config.BindAddress)
			if err == nil {
				break
			}
			Log.Warn("Failed to listen, retrying...", "attempt", i+1, "error", err)
			time.Sleep(2 * time.Second)
			select {
			case <-ctx.Done():
				return nil
			default:
			}
		}
		if err != nil {
			Log.Error("Failed to create listener after retries", "error", err)
			time.Sleep(5 * time.Second)
			continue
		}

		closeChan := make(chan struct{})
		go func() {
			<-ctx.Done()
			listener.Close()
			close(closeChan)
		}()

		Log.Info("SOCKS5 server started", "bind", config.BindAddress)
		err = server.Serve(listener)
		if ctx.Err() != nil {
			<-closeChan
			return nil
		}
		Log.Warn("SOCKS5 server stopped unexpectedly, restarting", "error", err)
		listener.Close()
		<-closeChan
		time.Sleep(5 * time.Second)
	}
}

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

func (conf *STDIOTunnelConfig) SpawnRoutine(ctx context.Context, vt *VirtualTun) error {
	raddr, err := parseAddressPort(conf.Target)
	if err != nil {
		return fmt.Errorf("parse target %s: %w", conf.Target, err)
	}
	go STDIOTcpForward(ctx, vt, raddr)
	return nil
}

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

func (conf *UDPProxyTunnelConfig) SpawnRoutine(ctx context.Context, vt *VirtualTun) error {
	return conf.SpawnUDPProxy(ctx, vt)
}

// ---------- Копирование данных с CloseRead/CloseWrite и пулом буферов ----------

func copyBidirectional(a, b net.Conn) {
	var wg sync.WaitGroup
	var closeA, closeB sync.Once

	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = CopyWithPool(b, a)
		closeB.Do(func() {
			if tcpConn, ok := b.(*net.TCPConn); ok {
				_ = tcpConn.CloseWrite()
			} else {
				_ = b.Close()
			}
		})
		closeA.Do(func() {
			if tcpConn, ok := a.(*net.TCPConn); ok {
				_ = tcpConn.CloseRead()
			} else {
				_ = a.Close()
			}
		})
	}()

	go func() {
		defer wg.Done()
		_, _ = CopyWithPool(a, b)
		closeA.Do(func() {
			if tcpConn, ok := a.(*net.TCPConn); ok {
				_ = tcpConn.CloseWrite()
			} else {
				_ = a.Close()
			}
		})
		closeB.Do(func() {
			if tcpConn, ok := b.(*net.TCPConn); ok {
				_ = tcpConn.CloseRead()
			} else {
				_ = b.Close()
			}
		})
	}()

	wg.Wait()
}

// ---------- TCP-туннели с семафором ----------

func tcpClientForward(ctx context.Context, vt *VirtualTun, raddr *addressPort, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			Log.Error("tcpClientForward panicked", "recover", r)
		}
	}()
	defer conn.Close()

	select {
	case tcpSemaphore <- struct{}{}:
		defer func() { <-tcpSemaphore }()
	case <-ctx.Done():
		return
	}

	target, err := vt.resolveToAddrPort(ctx, raddr)
	if err != nil {
		Log.Error("TCP Client Tunnel resolve error", "address", raddr.address, "error", err)
		return
	}
	tcpAddr := net.TCPAddrFromAddrPort(*target)
	sconn, err := defaultDialer.DialContext(ctx, "tcp", tcpAddr.String())
	if err != nil {
		Log.Error("TCP Client Tunnel dial error", "target", target, "error", err)
		return
	}
	defer sconn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(IdleTimeout))
	_ = conn.SetWriteDeadline(time.Now().Add(IdleTimeout))
	_ = sconn.SetReadDeadline(time.Now().Add(IdleTimeout))
	_ = sconn.SetWriteDeadline(time.Now().Add(IdleTimeout))

	copyDone := make(chan struct{})
	go func() {
		copyBidirectional(conn, sconn)
		close(copyDone)
	}()

	select {
	case <-copyDone:
	case <-ctx.Done():
		_ = conn.Close()
		_ = sconn.Close()
	}
}

func tcpServerForward(ctx context.Context, vt *VirtualTun, raddr *addressPort, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			Log.Error("tcpServerForward panicked", "recover", r)
		}
	}()
	defer conn.Close()

	select {
	case tcpSemaphore <- struct{}{}:
		defer func() { <-tcpSemaphore }()
	case <-ctx.Done():
		return
	}

	target, err := vt.resolveToAddrPort(ctx, raddr)
	if err != nil {
		Log.Error("TCP Server Tunnel resolve error", "address", raddr.address, "error", err)
		return
	}
	tcpAddr := net.TCPAddrFromAddrPort(*target)
	sconn, err := defaultDialer.DialContext(ctx, "tcp", tcpAddr.String())
	if err != nil {
		Log.Error("TCP Server Tunnel dial error", "target", target, "error", err)
		return
	}
	defer sconn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(IdleTimeout))
	_ = conn.SetWriteDeadline(time.Now().Add(IdleTimeout))
	_ = sconn.SetReadDeadline(time.Now().Add(IdleTimeout))
	_ = sconn.SetWriteDeadline(time.Now().Add(IdleTimeout))

	copyDone := make(chan struct{})
	go func() {
		copyBidirectional(conn, sconn)
		close(copyDone)
	}()

	select {
	case <-copyDone:
	case <-ctx.Done():
		_ = conn.Close()
		_ = sconn.Close()
	}
}

func STDIOTcpForward(ctx context.Context, vt *VirtualTun, raddr *addressPort) {
	defer func() {
		if r := recover(); r != nil {
			Log.Error("STDIOTcpForward panicked", "recover", r)
		}
	}()

	select {
	case tcpSemaphore <- struct{}{}:
		defer func() { <-tcpSemaphore }()
	case <-ctx.Done():
		return
	}

	target, err := vt.resolveToAddrPort(ctx, raddr)
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
	sconn, err := defaultDialer.DialContext(ctx, "tcp", tcpAddr.String())
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
		_, _ = CopyWithPool(sconn, os.Stdin)
	}()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				Log.Error("STDIOTcpForward copy goroutine 2 panicked", "recover", r)
			}
		}()
		_, _ = CopyWithPool(stdout, sconn)
	}()

	<-ctx.Done()
}

// ---------- ICMP ping с worker pool ----------

func (d *VirtualTun) initPingWorkers() {
	if d.pingJobs != nil {
		return
	}
	d.pingCtx, d.pingCancel = context.WithCancel(context.Background())
	d.pingJobs = make(chan pingJob, 10)

	for i := 0; i < 5; i++ {
		d.pingWorkers.Add(1)
		go d.pingWorker()
	}
}

func (d *VirtualTun) pingWorker() {
	defer d.pingWorkers.Done()
	for {
		select {
		case <-d.pingCtx.Done():
			return
		case job, ok := <-d.pingJobs:
			if !ok {
				return
			}
			d.doPing(job.addr, job.requestPing)
		}
	}
}

func (d *VirtualTun) stopPingWorkers() {
	if d.pingCancel != nil {
		d.pingCancel()
	}
	if d.pingJobs != nil {
		close(d.pingJobs)
	}
	d.pingWorkers.Wait()
}

func (d *VirtualTun) doPing(addr netip.Addr, requestPing icmp.Echo) {
	socket, err := d.Tnet.Dial("ping", addr.String())
	if err != nil {
		Log.Error("Failed to ping", "address", addr, "error", err)
		return
	}
	defer socket.Close()

	data := icmpBufPool.Get().([]byte)
	defer icmpBufPool.Put(data)

	var icmpBytes []byte
	if addr.Is4() {
		icmpBytes, _ = (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
	} else if addr.Is6() {
		icmpBytes, _ = (&icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Code: 0, Body: &requestPing}).Marshal(nil)
	} else {
		Log.Error("Failed to ping: invalid address", "address", addr)
		return
	}
	_ = socket.SetReadDeadline(time.Now().Add(time.Duration(d.Conf.CheckAliveInterval) * time.Second))
	_, err = socket.Write(icmpBytes)
	if err != nil {
		Log.Error("Failed to ping: write error", "address", addr, "error", err)
		return
	}
	n, err := socket.Read(data)
	if err != nil {
		Log.Error("Failed to read ping response", "address", addr, "error", err)
		return
	}
	replyPacket, err := icmp.ParseMessage(1, data[:n])
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
	} else if addr.Is6() {
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
}

func (d *VirtualTun) pingIPs() {
	if d.pingJobs == nil {
		d.initPingWorkers()
	}
	for _, addr := range d.Conf.CheckAlive {
		data := icmpBufPool.Get().([]byte)
		_, _ = srand.Read(data)
		requestPing := icmp.Echo{
			Seq:  rand.Intn(1 << 16),
			Data: data,
		}
		icmpBufPool.Put(data)

		select {
		case d.pingJobs <- pingJob{addr: addr, requestPing: requestPing}:
		case <-d.pingCtx.Done():
			return
		}
	}
}

// ---------- Health check и метрики ----------

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
		now := time.Now()
		ok := true
		for _, key := range d.PingRecord.Keys() {
			if val, okRec := d.PingRecord.Get(key); okRec {
				if now.Sub(time.Unix(int64(val), 0)) > time.Duration(d.Conf.CheckAliveInterval+2)*time.Second {
					ok = false
					break
				}
			} else {
				ok = false
				break
			}
		}
		if ok {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
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

// ---------- Старт/стоп пингов ----------

func (d *VirtualTun) StartPingIPs() {
	d.pingStopMu.Lock()
	defer d.pingStopMu.Unlock()

	ttl := time.Duration(d.Conf.CheckAliveInterval+2) * time.Second
	if d.PingRecord == nil {
		d.PingRecord = expirable.NewLRU[string, uint64](d.DnsCacheSize, nil, ttl)
	}

	for _, addr := range d.Conf.CheckAlive {
		d.PingRecord.Add(addr.String(), 0)
	}

	if d.pingStop != nil {
		return
	}
	d.pingStop = make(chan struct{})
	d.initPingWorkers()

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
			case <-d.pingStop:
				d.stopPingWorkers()
				return
			case <-ticker.C:
				d.pingIPs()
			}
		}
	}()
}

func (d *VirtualTun) StopPingIPs() {
	d.pingStopMu.Lock()
	defer d.pingStopMu.Unlock()
	if d.pingStop != nil {
		close(d.pingStop)
		d.pingStop = nil
	}
}
