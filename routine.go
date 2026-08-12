package wireproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
// Рассчитываем на основе количества CPU для лучшей масштабируемости
var tcpSemaphore = make(chan struct{}, runtime.GOMAXPROCS(0)*256)

// ---------- DNS перемешивание ----------

var (
	dnsRand   = rand.New(rand.NewSource(time.Now().UnixNano()))
	dnsRandMu sync.Mutex
)

// ---------- ICMP read buffer pool ----------

var icmpReadPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 128)
		return &b
	},
}

// ---------- ICMP sequence generator ----------

var pingSeq uint32

// ---------- Интерфейсы для half-close ----------

type closeWriter interface {
	CloseWrite() error
}

type closeReader interface {
	CloseRead() error
}

// ---------- timeoutConn с упрощённым управлением дедлайнами ----------

type timeoutConn struct {
	net.Conn
	idle time.Duration
}

func (c *timeoutConn) Read(p []byte) (int, error) {
	if c.idle > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Read(p)
}

func (c *timeoutConn) Write(p []byte) (int, error) {
	if c.idle > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Write(p)
}

func (c *timeoutConn) Close() error {
	_ = c.Conn.SetReadDeadline(time.Now())
	_ = c.Conn.SetWriteDeadline(time.Now())
	return c.Conn.Close()
}

// dialWithTimeout создаёт соединение через vt.Tnet.DialContext и оборачивает его в timeoutConn
func dialWithTimeout(ctx context.Context, network, addr string, vt *VirtualTun) (net.Conn, error) {
	conn, err := vt.Tnet.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &timeoutConn{
		Conn: conn,
		idle: IdleTimeout,
	}, nil
}

// timeoutListener оборачивает net.Listener и возвращает timeoutConn для каждого принятого соединения
type timeoutListener struct {
	net.Listener
	idle time.Duration
}

func (l *timeoutListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &timeoutConn{
		Conn: conn,
		idle: l.idle,
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

	PingRecord *expirable.LRU[string, uint64]

	pingStop   chan struct{}
	pingStopMu sync.Mutex
	pingLoopWg sync.WaitGroup

	DnsCacheSize        int
	UdpSessionCacheSize int
	DnsTtl              time.Duration

	pingJobs    chan pingJob
	pingWorkers sync.WaitGroup
	pingCtx     context.Context
	pingCancel  context.CancelFunc
	// Флаг, что workers запущены
	pingWorkersStarted bool
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
	// Используем глобальный PRNG с мьютексом вместо создания нового на каждый вызов
	dnsRandMu.Lock()
	dnsRand.Shuffle(size, func(i, j int) {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	})
	dnsRandMu.Unlock()

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

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialWithTimeout(ctx, network, addr, vt)
	}

	options := []socks5.Option{
		socks5.WithDial(dial),
		socks5.WithResolver(resolver),
		socks5.WithAuthMethods(authMethods),
		socks5.WithBufferPool(socksPool),
		socks5.WithUDPReadTimeout(IdleTimeout),
	}

	// Создаём server один раз, а не при каждой итерации
	server := socks5.NewServer(options...)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		rawListener, err := net.Listen("tcp", config.BindAddress)
		if err != nil {
			Log.Error("Failed to listen", "error", err)
			time.Sleep(5 * time.Second)
			continue
		}

		listener := &timeoutListener{
			Listener: rawListener,
			idle:     IdleTimeout,
		}

		// Запускаем горутину для закрытия listener при отмене контекста
		go func() {
			<-ctx.Done()
			rawListener.Close()
		}()

		Log.Info("SOCKS5 server started", "bind", config.BindAddress)
		err = server.Serve(listener)

		if ctx.Err() != nil {
			// Контекст отменён, listener уже закрыт, выходим
			return nil
		}

		// Если ошибка не от контекста, перезапускаем
		Log.Warn("SOCKS5 server stopped unexpectedly, restarting", "error", err)
		rawListener.Close()
		// Даём время на закрытие
		time.Sleep(100 * time.Millisecond)
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
		// Закрываем сторону записи b
		closeB.Do(func() {
			if cw, ok := b.(closeWriter); ok {
				_ = cw.CloseWrite()
			} else {
				_ = b.Close()
			}
		})
		// Закрываем сторону чтения a
		closeA.Do(func() {
			if cr, ok := a.(closeReader); ok {
				_ = cr.CloseRead()
			} else {
				_ = a.Close()
			}
		})
	}()

	go func() {
		defer wg.Done()
		_, _ = CopyWithPool(a, b)
		// Закрываем сторону записи a
		closeA.Do(func() {
			if cw, ok := a.(closeWriter); ok {
				_ = cw.CloseWrite()
			} else {
				_ = a.Close()
			}
		})
		// Закрываем сторону чтения b
		closeB.Do(func() {
			if cr, ok := b.(closeReader); ok {
				_ = cr.CloseRead()
			} else {
				_ = b.Close()
			}
		})
	}()

	wg.Wait()
}

// ---------- TCP-туннели с семафором (после resolve + dial) ----------

func tcpClientForward(ctx context.Context, vt *VirtualTun, raddr *addressPort, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			Log.Error("tcpClientForward panicked", "recover", r)
		}
	}()
	defer conn.Close()

	// Сначала разрешаем адрес и устанавливаем соединение
	target, err := vt.resolveToAddrPort(ctx, raddr)
	if err != nil {
		Log.Error("TCP Client Tunnel resolve error", "address", raddr.address, "error", err)
		return
	}
	tcpAddr := net.TCPAddrFromAddrPort(*target)

	// Используем dial через туннель (унифицируем)
	sconn, err := dialWithTimeout(ctx, "tcp", tcpAddr.String(), vt)
	if err != nil {
		Log.Error("TCP Client Tunnel dial error", "target", target, "error", err)
		return
	}
	defer sconn.Close()

	// Теперь захватываем семафор перед копированием
	select {
	case tcpSemaphore <- struct{}{}:
		defer func() { <-tcpSemaphore }()
	case <-ctx.Done():
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(IdleTimeout))
	_ = conn.SetWriteDeadline(time.Now().Add(IdleTimeout))
	_ = sconn.SetReadDeadline(time.Now().Add(IdleTimeout))
	_ = sconn.SetWriteDeadline(time.Now().Add(IdleTimeout))

	copyBidirectional(conn, sconn)
}

func tcpServerForward(ctx context.Context, vt *VirtualTun, raddr *addressPort, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			Log.Error("tcpServerForward panicked", "recover", r)
		}
	}()
	defer conn.Close()

	target, err := vt.resolveToAddrPort(ctx, raddr)
	if err != nil {
		Log.Error("TCP Server Tunnel resolve error", "address", raddr.address, "error", err)
		return
	}
	tcpAddr := net.TCPAddrFromAddrPort(*target)

	sconn, err := dialWithTimeout(ctx, "tcp", tcpAddr.String(), vt)
	if err != nil {
		Log.Error("TCP Server Tunnel dial error", "target", target, "error", err)
		return
	}
	defer sconn.Close()

	select {
	case tcpSemaphore <- struct{}{}:
		defer func() { <-tcpSemaphore }()
	case <-ctx.Done():
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(IdleTimeout))
	_ = conn.SetWriteDeadline(time.Now().Add(IdleTimeout))
	_ = sconn.SetReadDeadline(time.Now().Add(IdleTimeout))
	_ = sconn.SetWriteDeadline(time.Now().Add(IdleTimeout))

	copyBidirectional(conn, sconn)
}

func STDIOTcpForward(ctx context.Context, vt *VirtualTun, raddr *addressPort) {
	defer func() {
		if r := recover(); r != nil {
			Log.Error("STDIOTcpForward panicked", "recover", r)
		}
	}()

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
	sconn, err := dialWithTimeout(ctx, "tcp", tcpAddr.String(), vt)
	if err != nil {
		Log.Error("TCP Client Tunnel dial error", "target", target, "tcpAddr", tcpAddr, "error", err)
		return
	}
	defer sconn.Close()

	select {
	case tcpSemaphore <- struct{}{}:
		defer func() { <-tcpSemaphore }()
	case <-ctx.Done():
		return
	}

	_ = stdout.SetReadDeadline(time.Now().Add(IdleTimeout))
	_ = stdout.SetWriteDeadline(time.Now().Add(IdleTimeout))
	_ = sconn.SetReadDeadline(time.Now().Add(IdleTimeout))
	_ = sconn.SetWriteDeadline(time.Now().Add(IdleTimeout))

	var wg sync.WaitGroup
	wg.Add(2)

	done := make(chan struct{}, 1)

	go func() {
		defer wg.Done()
		_, _ = CopyWithPool(sconn, os.Stdin)
		// при завершении копирования закрываем sconn для записи
		if cw, ok := sconn.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = sconn.Close()
		}
		select {
		case done <- struct{}{}:
		default:
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = CopyWithPool(stdout, sconn)
		// при завершении копирования закрываем stdout (хотя это не обязательно)
		// и sconn для чтения
		if cr, ok := sconn.(closeReader); ok {
			_ = cr.CloseRead()
		} else {
			_ = sconn.Close()
		}
		select {
		case done <- struct{}{}:
		default:
		}
	}()

	// Ждём либо ctx.Done(), либо завершения одной из копий
	select {
	case <-ctx.Done():
		_ = sconn.Close()
		_ = stdout.Close()
	case <-done:
		// Одна сторона завершилась, вторая тоже выйдет после Close()
		_ = sconn.Close()
		_ = stdout.Close()
	}

	wg.Wait()
}

// ---------- ICMP ping с worker pool (исправленный) ----------

func (d *VirtualTun) initPingWorkers() {
	if d.pingWorkersStarted {
		return
	}
	if d.pingJobs == nil {
		d.pingCtx, d.pingCancel = context.WithCancel(context.Background())
		workers := runtime.GOMAXPROCS(0)
		if workers < 2 {
			workers = 2
		}
		queueSize := workers * 16
		d.pingJobs = make(chan pingJob, queueSize)

		for i := 0; i < workers; i++ {
			d.pingWorkers.Add(1)
			go d.pingWorker()
		}
		d.pingWorkersStarted = true
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
	if !d.pingWorkersStarted {
		return
	}
	if d.pingCancel != nil {
		d.pingCancel()
		d.pingCancel = nil
	}
	if d.pingJobs != nil {
		close(d.pingJobs)
		d.pingJobs = nil
	}
	d.pingWorkers.Wait()
	d.pingWorkersStarted = false
}

func (d *VirtualTun) doPing(addr netip.Addr, requestPing icmp.Echo) {
	socket, err := d.Tnet.Dial("ping", addr.String())
	if err != nil {
		Log.Error("Failed to ping", "address", addr, "error", err)
		return
	}
	defer socket.Close()

	var data [16]byte
	copy(data[:], requestPing.Data)

	reqPing := icmp.Echo{
		Seq:  requestPing.Seq,
		Data: data[:],
	}

	var icmpBytes []byte
	if addr.Is4() {
		icmpBytes, _ = (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &reqPing}).Marshal(nil)
	} else if addr.Is6() {
		icmpBytes, _ = (&icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Code: 0, Body: &reqPing}).Marshal(nil)
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
	bufPtr := icmpReadPool.Get().(*[]byte)
	readBuf := *bufPtr
	defer icmpReadPool.Put(bufPtr)

	n, err := socket.Read(readBuf)
	if err != nil {
		Log.Error("Failed to read ping response", "address", addr, "error", err)
		return
	}

	// Определяем протокол для разбора ответа
	var proto int
	if addr.Is4() {
		proto = 1 // ICMPv4
	} else if addr.Is6() {
		proto = 58 // ICMPv6
	} else {
		Log.Error("Failed to parse ping response: invalid address type", "address", addr)
		return
	}

	replyPacket, err := icmp.ParseMessage(proto, readBuf[:n])
	if err != nil {
		Log.Error("Failed to parse ping response", "address", addr, "error", err)
		return
	}

	// Обрабатываем ответ в зависимости от протокола
	if addr.Is4() {
		replyPing, ok := replyPacket.Body.(*icmp.Echo)
		if !ok {
			Log.Error("Failed to parse ping response: invalid reply type", "address", addr, "type", replyPacket.Type)
			return
		}
		if !bytes.Equal(replyPing.Data, reqPing.Data) || replyPing.Seq != reqPing.Seq {
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
		if !bytes.Equal(pongBody, reqPing.Data) || int(seq) != reqPing.Seq {
			Log.Error("Failed to parse ping response: invalid ping reply", "address", addr, "reply", replyPing)
			return
		}
	}
	d.PingRecord.Add(addr.String(), uint64(time.Now().Unix()))
}

func (d *VirtualTun) pingIPs() {
	if !d.pingWorkersStarted {
		d.initPingWorkers()
	}
	if d.pingJobs == nil {
		return
	}
	seq := atomic.AddUint32(&pingSeq, 1)
	for _, addr := range d.Conf.CheckAlive {
		var data [16]byte
		binary.BigEndian.PutUint32(data[:4], seq)
		binary.BigEndian.PutUint64(data[8:], uint64(time.Now().UnixNano()))

		requestPing := icmp.Echo{
			Seq:  int(seq),
			Data: data[:],
		}

		select {
		case d.pingJobs <- pingJob{
			addr:        addr,
			requestPing: requestPing,
		}:
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
	// Снижаем уровень лога для health-запросов
	if r.URL.Path == "/metrics" || r.URL.Path == "/readyz" {
		Log.Debug("Health metric request", "path", r.URL.Path)
	} else {
		Log.Info("HTTP request", "path", r.URL.Path)
	}
	switch path.Clean(r.URL.Path) {
	case "/readyz":
		now := time.Now()
		ok := true
		for _, addr := range d.Conf.CheckAlive {
			key := addr.String()
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
		scanner := bufio.NewScanner(strings.NewReader(get))
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			pair := strings.SplitN(line, "=", 2)
			if len(pair) != 2 {
				buf.WriteString(line)
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

// ---------- Старт/стоп пингов (исправленные) ----------

func (d *VirtualTun) StartPingIPs() {
	d.pingStopMu.Lock()
	defer d.pingStopMu.Unlock()

	if d.pingStop != nil {
		return
	}

	ttl := time.Duration(d.Conf.CheckAliveInterval+2) * time.Second
	if d.PingRecord == nil {
		d.PingRecord = expirable.NewLRU[string, uint64](d.DnsCacheSize, nil, ttl)
	}

	for _, addr := range d.Conf.CheckAlive {
		if _, ok := d.PingRecord.Get(addr.String()); !ok {
			d.PingRecord.Add(addr.String(), 0)
		}
	}

	d.pingStop = make(chan struct{})
	d.pingLoopWg.Add(1)
	go d.runPingLoop()
}

func (d *VirtualTun) runPingLoop() {
	defer d.pingLoopWg.Done()
	defer func() {
		if r := recover(); r != nil {
			Log.Error("Ping loop panicked", "recover", r)
			// При панике останавливаем workers, чтобы не было утечки
			d.stopPingWorkers()
		}
	}()

	d.initPingWorkers()
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
}

func (d *VirtualTun) StopPingIPs() {
	d.pingStopMu.Lock()
	defer d.pingStopMu.Unlock()

	if d.pingStop != nil {
		close(d.pingStop)
		d.pingStop = nil
	}
	d.pingLoopWg.Wait()
}
