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

	"github.com/ageich/go-socks5"
	"github.com/ageich/go-socks5/bufferpool"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/hashicorp/golang-lru/v2/expirable"
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

// Ограничивает только одновременно выполняемые операции:
//
//	resolve DNS + Dial
//
// После успешного Dial semaphore освобождается.
// Длительные TCP-соединения semaphore НЕ занимают.
var tcpSemaphore = make(
	chan struct{},
	runtime.GOMAXPROCS(0)*256,
)

// ---------- DNS перемешивание ----------

var (
	dnsRand   = rand.New(rand.NewSource(time.Now().UnixNano()))
	dnsRandMu sync.Mutex
)

// ---------- ICMP read buffer pool ----------

var icmpReadPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 1500)
		return &b
	},
}

// ---------- ICMP sequence generator ----------

var pingSeq uint32

// ---------- Интерфейсы half-close ----------

type closeWriter interface {
	CloseWrite() error
}

type closeReader interface {
	CloseRead() error
}

var errHalfCloseUnsupported = errors.New(
	"half-close is not supported",
)

// ---------- timeoutConn ----------

// timeoutConn обновляет idle deadline только при необходимости.
//
// Внутри atomic.Int64 хранится deadline в UnixNano.
//
// Важно:
// time.Duration нельзя напрямую вычитать из int64,
// поэтому перед сравнением duration преобразуется через Nanoseconds().
type timeoutConn struct {
	net.Conn

	idle time.Duration

	readDeadline  atomic.Int64
	writeDeadline atomic.Int64
}

func (c *timeoutConn) Read(p []byte) (int, error) {
	now := time.Now()
	nowUnix := now.UnixNano()

	deadline := c.readDeadline.Load()

	refreshBefore := (c.idle / 10).Nanoseconds()
	if refreshBefore <= 0 {
		refreshBefore = int64(time.Nanosecond)
	}

	if deadline == 0 || nowUnix >= deadline-refreshBefore {
		newDeadline := now.Add(c.idle)
		newDeadlineUnix := newDeadline.UnixNano()

		if c.readDeadline.CompareAndSwap(
			deadline,
			newDeadlineUnix,
		) {
			_ = c.Conn.SetReadDeadline(newDeadline)
		}
	}

	return c.Conn.Read(p)
}

func (c *timeoutConn) Write(p []byte) (int, error) {
	now := time.Now()
	nowUnix := now.UnixNano()

	deadline := c.writeDeadline.Load()

	refreshBefore := (c.idle / 10).Nanoseconds()
	if refreshBefore <= 0 {
		refreshBefore = int64(time.Nanosecond)
	}

	if deadline == 0 || nowUnix >= deadline-refreshBefore {
		newDeadline := now.Add(c.idle)
		newDeadlineUnix := newDeadline.UnixNano()

		if c.writeDeadline.CompareAndSwap(
			deadline,
			newDeadlineUnix,
		) {
			_ = c.Conn.SetWriteDeadline(newDeadline)
		}
	}

	return c.Conn.Write(p)
}

func (c *timeoutConn) Close() error {
	return c.Conn.Close()
}

// CloseWrite сохраняет TCP half-close.
//
// Если underlying connection поддерживает CloseWrite,
// используется он. Иначе возвращается ошибка.
func (c *timeoutConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}

	return errHalfCloseUnsupported
}

// CloseRead сохраняет TCP half-close.
//
// Если underlying connection поддерживает CloseRead,
// используется он. Иначе возвращается ошибка.
func (c *timeoutConn) CloseRead() error {
	if cr, ok := c.Conn.(closeReader); ok {
		return cr.CloseRead()
	}

	return errHalfCloseUnsupported
}

// ---------- Dial ----------

// dialWithTimeout создаёт соединение через vt.Tnet.DialContext
// и оборачивает его в timeoutConn.
func dialWithTimeout(
	ctx context.Context,
	network string,
	addr string,
	vt *VirtualTun,
) (net.Conn, error) {
	conn, err := vt.Tnet.DialContext(
		ctx,
		network,
		addr,
	)
	if err != nil {
		return nil, err
	}

	return &timeoutConn{
		Conn: conn,
		idle: IdleTimeout,
	}, nil
}

// ---------- timeoutListener ----------

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

func (c CredentialValidator) Valid(
	username,
	password string,
) bool {
	u := subtle.ConstantTimeCompare(
		[]byte(c.username),
		[]byte(username),
	)

	p := subtle.ConstantTimeCompare(
		[]byte(c.password),
		[]byte(password),
	)

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

	// Ping worker pool.
	pingMu             sync.Mutex
	pingJobs           chan pingJob
	pingWorkers        sync.WaitGroup
	pingCtx            context.Context
	pingCancel         context.CancelFunc
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

func (d *VirtualTun) LookupAddr(
	ctx context.Context,
	name string,
) ([]string, error) {
	if d.SystemDNS {
		return net.DefaultResolver.LookupHost(
			ctx,
			name,
		)
	}

	return d.Tnet.LookupContextHost(
		ctx,
		name,
	)
}

func (d *VirtualTun) ResolveAddrWithContext(
	ctx context.Context,
	name string,
) (*netip.Addr, error) {
	addrs, err := d.LookupAddr(ctx, name)
	if err != nil {
		return nil, err
	}

	size := len(addrs)
	if size == 0 {
		return nil, errors.New(
			"no address found for: " + name,
		)
	}

	dnsRandMu.Lock()

	dnsRand.Shuffle(
		size,
		func(i, j int) {
			addrs[i], addrs[j] =
				addrs[j], addrs[i]
		},
	)

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

func (d *VirtualTun) Resolve(
	ctx context.Context,
	name string,
) (context.Context, net.IP, error) {
	addr, err := d.ResolveAddrWithContext(
		ctx,
		name,
	)
	if err != nil {
		return nil, nil, err
	}

	return ctx, addr.AsSlice(), nil
}

func parseAddressPort(
	endpoint string,
) (*addressPort, error) {
	name, sport, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return nil, &net.OpError{
			Op: "dial",
			Err: errors.New(
				"port must be numeric",
			),
		}
	}

	return &addressPort{
		address: name,
		port:    uint16(port),
	}, nil
}

func (d *VirtualTun) resolveToAddrPort(
	ctx context.Context,
	endpoint *addressPort,
) (*netip.AddrPort, error) {
	addr, err := d.ResolveAddrWithContext(
		ctx,
		endpoint.address,
	)
	if err != nil {
		return nil, err
	}

	addrPort := netip.AddrPortFrom(
		*addr,
		endpoint.port,
	)

	return &addrPort, nil
}

// ---------- TCP Dial + semaphore ----------

// Ограничивает только установление исходящего TCP-соединения:
//
//	Acquire
//	    |
//	    +-- DNS resolve
//	    |
//	    +-- Tnet.DialContext
//	    |
//	Release
//
// После Release TCP-соединение может жить часами,
// не занимая semaphore.
func dialTCPWithSemaphore(
	ctx context.Context,
	vt *VirtualTun,
	raddr *addressPort,
) (net.Conn, error) {
	select {
	case tcpSemaphore <- struct{}{}:
		defer func() {
			<-tcpSemaphore
		}()

	case <-ctx.Done():
		return nil, ctx.Err()
	}

	target, err := vt.resolveToAddrPort(
		ctx,
		raddr,
	)
	if err != nil {
		return nil, err
	}

	tcpAddr := net.TCPAddrFromAddrPort(
		*target,
	)

	return dialWithTimeout(
		ctx,
		"tcp",
		tcpAddr.String(),
		vt,
	)
}

// ---------- SpawnRoutine implementations ----------

func (config *Socks5Config) SpawnRoutine(
	ctx context.Context,
	vt *VirtualTun,
) error {
	resolver := NewFixedResolver(
		vt.Tnet,
		vt.SystemDNS,
		vt.DnsTtl,
		vt.DnsCacheSize,
	)

	config.resolver = resolver

	var authMethods []socks5.Authenticator

	if username := config.Username; username != "" {
		authMethods = append(
			authMethods,
			socks5.UserPassAuthenticator{
				Credentials: socks5.StaticCredentials{
					username: config.Password,
				},
			},
		)
	} else {
		authMethods = append(
			authMethods,
			socks5.NoAuthAuthenticator{},
		)
	}

	dial := func(
		ctx context.Context,
		network,
		addr string,
	) (net.Conn, error) {
		return dialWithTimeout(
			ctx,
			network,
			addr,
			vt,
		)
	}

	options := []socks5.Option{
		socks5.WithDial(dial),
		socks5.WithResolver(resolver),
		socks5.WithAuthMethods(authMethods),
		socks5.WithBufferPool(socksPool),
		socks5.WithUDPReadTimeout(IdleTimeout),
	}

	server := socks5.NewServer(options...)

	for {
		select {
		case <-ctx.Done():
			return nil

		default:
		}

		rawListener, err := net.Listen(
			"tcp",
			config.BindAddress,
		)
		if err != nil {
			Log.Error(
				"Failed to listen",
				"error",
				err,
			)

			select {
			case <-ctx.Done():
				return nil

			case <-time.After(5 * time.Second):
			}

			continue
		}

		listener := &timeoutListener{
			Listener: rawListener,
			idle:     IdleTimeout,
		}

		go func(l net.Listener) {
			<-ctx.Done()
			_ = l.Close()
		}(rawListener)

		Log.Info(
			"SOCKS5 server started",
			"bind",
			config.BindAddress,
		)

		err = server.Serve(listener)

		if ctx.Err() != nil {
			_ = rawListener.Close()
			return nil
		}

		Log.Warn(
			"SOCKS5 server stopped unexpectedly, restarting",
			"error",
			err,
		)

		_ = rawListener.Close()

		select {
		case <-ctx.Done():
			return nil

		case <-time.After(5 * time.Second):
		}
	}
}

func (config *HTTPConfig) SpawnRoutine(
	ctx context.Context,
	vt *VirtualTun,
) error {
	server := NewHTTPServer(
		config,
		vt.Tnet.Dial,
	)

	if err := server.ListenAndServe(
		ctx,
		"tcp",
		config.BindAddress,
	); err != nil {
		select {
		case <-ctx.Done():
			return nil

		default:
			return fmt.Errorf(
				"HTTP server error: %w",
				err,
			)
		}
	}

	return nil
}

// TCPClientTunnelConfig.BindAddress имеет тип *net.TCPAddr.
// Поэтому используется net.ListenTCP().
func (conf *TCPClientTunnelConfig) SpawnRoutine(
	ctx context.Context,
	vt *VirtualTun,
) error {
	raddr, err := parseAddressPort(
		conf.Target,
	)
	if err != nil {
		return fmt.Errorf(
			"parse target %s: %w",
			conf.Target,
			err,
		)
	}

	if conf.BindAddress == nil {
		return errors.New(
			"TCP client bind address is nil",
		)
	}

	server, err := net.ListenTCP(
		"tcp",
		conf.BindAddress,
	)
	if err != nil {
		return fmt.Errorf(
			"listen on %s: %w",
			conf.BindAddress,
			err,
		)
	}

	defer server.Close()

	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()

	for {
		conn, err := server.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil

			default:
				return fmt.Errorf(
					"accept error: %w",
					err,
				)
			}
		}

		go tcpClientForward(
			ctx,
			vt,
			raddr,
			conn,
		)
	}
}

func (conf *STDIOTunnelConfig) SpawnRoutine(
	ctx context.Context,
	vt *VirtualTun,
) error {
	raddr, err := parseAddressPort(
		conf.Target,
	)
	if err != nil {
		return fmt.Errorf(
			"parse target %s: %w",
			conf.Target,
			err,
		)
	}

	go STDIOTcpForward(
		ctx,
		vt,
		raddr,
	)

	return nil
}

func (conf *TCPServerTunnelConfig) SpawnRoutine(
	ctx context.Context,
	vt *VirtualTun,
) error {
	raddr, err := parseAddressPort(
		conf.Target,
	)
	if err != nil {
		return fmt.Errorf(
			"parse target %s: %w",
			conf.Target,
			err,
		)
	}

	addr := &net.TCPAddr{
		Port: conf.ListenPort,
	}

	server, err := vt.Tnet.ListenTCP(addr)
	if err != nil {
		return fmt.Errorf(
			"listen on wireguard port %d: %w",
			conf.ListenPort,
			err,
		)
	}

	defer server.Close()

	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()

	for {
		conn, err := server.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil

			default:
				return fmt.Errorf(
					"accept error: %w",
					err,
				)
			}
		}

		go tcpServerForward(
			ctx,
			vt,
			raddr,
			conn,
		)
	}
}

func (conf *UDPProxyTunnelConfig) SpawnRoutine(
	ctx context.Context,
	vt *VirtualTun,
) error {
	return conf.SpawnUDPProxy(
		ctx,
		vt,
	)
}

// ---------- Bidirectional copy ----------

func closeWriteOrClose(conn net.Conn) {
	if cw, ok := conn.(closeWriter); ok {
		if err := cw.CloseWrite(); err == nil {
			return
		}
	}

	_ = conn.Close()
}

func closeReadOrClose(conn net.Conn) {
	if cr, ok := conn.(closeReader); ok {
		if err := cr.CloseRead(); err == nil {
			return
		}
	}

	_ = conn.Close()
}

// copyBidirectional выполняет full-duplex copy.
//
// При EOF:
//
//	a -> b:
//	    CloseWrite(b)
//	    CloseRead(a)
//
//	b -> a:
//	    CloseWrite(a)
//	    CloseRead(b)
//
// Это позволяет сохранять TCP half-close.
func copyBidirectional(
	a,
	b net.Conn,
) {
	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		_, _ = CopyWithPool(
			b,
			a,
		)

		closeWriteOrClose(b)
		closeReadOrClose(a)
	}()

	go func() {
		defer wg.Done()

		_, _ = CopyWithPool(
			a,
			b,
		)

		closeWriteOrClose(a)
		closeReadOrClose(b)
	}()

	wg.Wait()
}

// ---------- TCP tunnels ----------

func tcpClientForward(
	ctx context.Context,
	vt *VirtualTun,
	raddr *addressPort,
	conn net.Conn,
) {
	defer func() {
		if r := recover(); r != nil {
			Log.Error(
				"tcpClientForward panicked",
				"recover",
				r,
			)
		}
	}()

	defer conn.Close()

	sconn, err := dialTCPWithSemaphore(
		ctx,
		vt,
		raddr,
	)
	if err != nil {
		Log.Error(
			"TCP Client Tunnel dial error",
			"address",
			raddr.address,
			"port",
			raddr.port,
			"error",
			err,
		)

		return
	}

	defer sconn.Close()

	// semaphore уже освобождён.
	copyBidirectional(
		conn,
		sconn,
	)
}

func tcpServerForward(
	ctx context.Context,
	vt *VirtualTun,
	raddr *addressPort,
	conn net.Conn,
) {
	defer func() {
		if r := recover(); r != nil {
			Log.Error(
				"tcpServerForward panicked",
				"recover",
				r,
			)
		}
	}()

	defer conn.Close()

	sconn, err := dialTCPWithSemaphore(
		ctx,
		vt,
		raddr,
	)
	if err != nil {
		Log.Error(
			"TCP Server Tunnel dial error",
			"address",
			raddr.address,
			"port",
			raddr.port,
			"error",
			err,
		)

		return
	}

	defer sconn.Close()

	copyBidirectional(
		conn,
		sconn,
	)
}

func STDIOTcpForward(
	ctx context.Context,
	vt *VirtualTun,
	raddr *addressPort,
) {
	defer func() {
		if r := recover(); r != nil {
			Log.Error(
				"STDIOTcpForward panicked",
				"recover",
				r,
			)
		}
	}()

	sconn, err := dialTCPWithSemaphore(
		ctx,
		vt,
		raddr,
	)
	if err != nil {
		Log.Error(
			"STDIO TCP Tunnel dial error",
			"address",
			raddr.address,
			"port",
			raddr.port,
			"error",
			err,
		)

		return
	}

	defer sconn.Close()

	stdout, err := os.OpenFile(
		"/dev/stdout",
		os.O_WRONLY,
		0,
	)
	if err != nil {
		Log.Error(
			"Failed to open /dev/stdout",
			"error",
			err,
		)

		return
	}

	defer stdout.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	done := make(chan struct{}, 1)

	go func() {
		defer wg.Done()

		_, _ = CopyWithPool(
			sconn,
			os.Stdin,
		)

		closeWriteOrClose(sconn)

		select {
		case done <- struct{}{}:
		default:
		}
	}()

	go func() {
		defer wg.Done()

		_, _ = CopyWithPool(
			stdout,
			sconn,
		)

		closeReadOrClose(sconn)

		select {
		case done <- struct{}{}:
		default:
		}
	}()

	select {
	case <-ctx.Done():
		_ = sconn.Close()
		_ = stdout.Close()

	case <-done:
		_ = sconn.Close()
		_ = stdout.Close()
	}

	wg.Wait()
}

// ---------- ICMP ping worker pool ----------

func (d *VirtualTun) initPingWorkers() {
	d.pingMu.Lock()
	defer d.pingMu.Unlock()

	if d.pingWorkersStarted {
		return
	}

	pingCtx, cancel := context.WithCancel(
		context.Background(),
	)

	workers := runtime.GOMAXPROCS(0)

	if workers < 2 {
		workers = 2
	}

	queueSize := workers * 8

	if queueSize < 16 {
		queueSize = 16
	}

	if queueSize > 256 {
		queueSize = 256
	}

	d.pingCtx = pingCtx
	d.pingCancel = cancel

	d.pingJobs = make(
		chan pingJob,
		queueSize,
	)

	for i := 0; i < workers; i++ {
		d.pingWorkers.Add(1)
		go d.pingWorker()
	}

	d.pingWorkersStarted = true
}

func (d *VirtualTun) pingWorker() {
	defer d.pingWorkers.Done()

	d.pingMu.Lock()

	jobs := d.pingJobs
	ctx := d.pingCtx

	d.pingMu.Unlock()

	if jobs == nil || ctx == nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return

		case job := <-jobs:
			d.doPing(
				job.addr,
				job.requestPing,
			)
		}
	}
}

func (d *VirtualTun) stopPingWorkers() {
	d.pingMu.Lock()

	if !d.pingWorkersStarted {
		d.pingMu.Unlock()
		return
	}

	cancel := d.pingCancel

	d.pingMu.Unlock()

	if cancel != nil {
		cancel()
	}

	d.pingWorkers.Wait()

	d.pingMu.Lock()

	d.pingCancel = nil
	d.pingCtx = nil
	d.pingJobs = nil
	d.pingWorkersStarted = false

	d.pingMu.Unlock()
}

func (d *VirtualTun) doPing(
	addr netip.Addr,
	requestPing icmp.Echo,
) {
	if d.Tnet == nil {
		return
	}

	socket, err := d.Tnet.Dial(
		"ping",
		addr.String(),
	)
	if err != nil {
		Log.Error(
			"Failed to ping",
			"address",
			addr,
			"error",
			err,
		)

		return
	}

	defer socket.Close()

	var data [16]byte

	copy(
		data[:],
		requestPing.Data,
	)

	reqPing := icmp.Echo{
		Seq:  requestPing.Seq,
		Data: data[:],
	}

	var (
		icmpBytes []byte
		proto     int
	)

	if addr.Is4() {
		proto = 1

		message := &icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &reqPing,
		}

		icmpBytes, err = message.Marshal(nil)
	} else if addr.Is6() {
		proto = 58

		message := &icmp.Message{
			Type: ipv6.ICMPTypeEchoRequest,
			Code: 0,
			Body: &reqPing,
		}

		icmpBytes, err = message.Marshal(nil)
	} else {
		Log.Error(
			"Failed to ping: invalid address",
			"address",
			addr,
		)

		return
	}

	if err != nil {
		Log.Error(
			"Failed to marshal ping",
			"address",
			addr,
			"error",
			err,
		)

		return
	}

	timeout := time.Duration(
		d.Conf.CheckAliveInterval,
	) * time.Second

	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	_ = socket.SetReadDeadline(
		time.Now().Add(timeout),
	)

	if _, err = socket.Write(icmpBytes); err != nil {
		Log.Error(
			"Failed to ping: write error",
			"address",
			addr,
			"error",
			err,
		)

		return
	}

	bufPtr := icmpReadPool.Get().(*[]byte)
	readBuf := *bufPtr

	defer icmpReadPool.Put(bufPtr)

	n, err := socket.Read(readBuf)
	if err != nil {
		Log.Error(
			"Failed to read ping response",
			"address",
			addr,
			"error",
			err,
		)

		return
	}

	if n <= 0 || n > len(readBuf) {
		return
	}

	replyPacket, err := icmp.ParseMessage(
		proto,
		readBuf[:n],
	)
	if err != nil {
		Log.Error(
			"Failed to parse ping response",
			"address",
			addr,
			"error",
			err,
		)

		return
	}

	if addr.Is4() {
		replyPing, ok := replyPacket.Body.(*icmp.Echo)
		if !ok {
			Log.Error(
				"Failed to parse ping response: invalid reply type",
				"address",
				addr,
				"type",
				replyPacket.Type,
			)

			return
		}

		if !bytes.Equal(
			replyPing.Data,
			reqPing.Data,
		) || replyPing.Seq != reqPing.Seq {
			Log.Error(
				"Failed to parse ping response: invalid ping reply",
				"address",
				addr,
				"reply",
				replyPing,
			)

			return
		}
	} else {
		replyPing, ok := replyPacket.Body.(*icmp.RawBody)
		if !ok {
			Log.Error(
				"Failed to parse ping response: invalid reply type",
				"address",
				addr,
				"type",
				replyPacket.Type,
			)

			return
		}

		if len(replyPing.Data) < 4 {
			Log.Error(
				"Failed to parse ping response: packet too short",
				"address",
				addr,
			)

			return
		}

		seq := binary.BigEndian.Uint16(
			replyPing.Data[2:4],
		)

		pongBody := replyPing.Data[4:]

		if !bytes.Equal(
			pongBody,
			reqPing.Data,
		) || int(seq) != reqPing.Seq {
			Log.Error(
				"Failed to parse ping response: invalid ping reply",
				"address",
				addr,
				"reply",
				replyPing,
			)

			return
		}
	}

	if d.PingRecord == nil {
		return
	}

	d.PingRecord.Add(
		addr.String(),
		uint64(time.Now().Unix()),
	)
}

func (d *VirtualTun) pingIPs() {
	d.pingMu.Lock()

	pingJobs := d.pingJobs
	pingCtx := d.pingCtx

	d.pingMu.Unlock()

	if pingJobs == nil || pingCtx == nil {
		return
	}

	select {
	case <-pingCtx.Done():
		return

	default:
	}

	seq := atomic.AddUint32(
		&pingSeq,
		1,
	)

	nowUnixNano := uint64(
		time.Now().UnixNano(),
	)

	for _, addr := range d.Conf.CheckAlive {
		var data [16]byte

		binary.BigEndian.PutUint32(
			data[:4],
			seq,
		)

		binary.BigEndian.PutUint64(
			data[8:],
			nowUnixNano,
		)

		requestPing := icmp.Echo{
			Seq:  int(seq),
			Data: data[:],
		}

		select {
		case pingJobs <- pingJob{
			addr:        addr,
			requestPing: requestPing,
		}:

		case <-pingCtx.Done():
			return
		}
	}
}

// ---------- HTTP health / metrics ----------

func (d *VirtualTun) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
) {
	defer func() {
		if recovered := recover(); recovered != nil {
			Log.Error(
				"ServeHTTP panicked",
				"recover",
				recovered,
			)

			w.WriteHeader(
				http.StatusInternalServerError,
			)
		}
	}()

	switch path.Clean(r.URL.Path) {
	case "/readyz":
		if d.PingRecord == nil {
			w.WriteHeader(
				http.StatusServiceUnavailable,
			)

			return
		}

		now := time.Now()

		interval := time.Duration(
			d.Conf.CheckAliveInterval,
		) * time.Second

		if interval <= 0 {
			interval = 5 * time.Second
		}

		ttl := interval + 2*time.Second

		ok := true

		for _, addr := range d.Conf.CheckAlive {
			key := addr.String()

			val, okRec := d.PingRecord.Get(key)

			if !okRec || val == 0 {
				ok = false
				break
			}

			if now.Sub(
				time.Unix(int64(val), 0),
			) > ttl {
				ok = false
				break
			}
		}

		if ok {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(
				http.StatusServiceUnavailable,
			)
		}

		_, _ = w.Write([]byte("\n"))

	case "/metrics":
		if d.Dev == nil {
			w.WriteHeader(
				http.StatusInternalServerError,
			)

			return
		}

		get, err := d.Dev.IpcGet()
		if err != nil {
			Log.Error(
				"Failed to get device metrics",
				"error",
				err,
			)

			w.WriteHeader(
				http.StatusInternalServerError,
			)

			return
		}

		var buf bytes.Buffer

		scanner := bufio.NewScanner(
			strings.NewReader(get),
		)

		for scanner.Scan() {
			line := scanner.Text()

			if line == "" {
				continue
			}

			pair := strings.SplitN(
				line,
				"=",
				2,
			)

			if len(pair) != 2 {
				buf.WriteString(line)
				buf.WriteByte('\n')
				continue
			}

			if pair[0] == "private_key" ||
				pair[0] == "preshared_key" {
				pair[1] = "REDACTED"
			}

			buf.WriteString(pair[0])
			buf.WriteByte('=')
			buf.WriteString(pair[1])
			buf.WriteByte('\n')
		}

		w.WriteHeader(http.StatusOK)

		_, _ = w.Write(
			buf.Bytes(),
		)

	default:
		Log.Info(
			"HTTP request",
			"path",
			r.URL.Path,
		)

		w.WriteHeader(
			http.StatusNotFound,
		)
	}
}

// ---------- Ping lifecycle ----------

func (d *VirtualTun) StartPingIPs() {
	d.pingStopMu.Lock()
	defer d.pingStopMu.Unlock()

	if d.pingStop != nil {
		return
	}

	ttl := time.Duration(
		d.Conf.CheckAliveInterval+2,
	) * time.Second

	if ttl <= 0 {
		ttl = 7 * time.Second
	}

	cacheSize := d.DnsCacheSize

	if cacheSize < len(d.Conf.CheckAlive) {
		cacheSize = len(d.Conf.CheckAlive)
	}

	if cacheSize < 1 {
		cacheSize = 1
	}

	if d.PingRecord == nil {
		d.PingRecord = expirable.NewLRU[
			string,
			uint64,
		](
			cacheSize,
			nil,
			ttl,
		)
	}

	for _, addr := range d.Conf.CheckAlive {
		if _, ok := d.PingRecord.Get(
			addr.String(),
		); !ok {
			d.PingRecord.Add(
				addr.String(),
				0,
			)
		}
	}

	d.pingStop = make(chan struct{})

	d.pingLoopWg.Add(1)

	stop := d.pingStop

	go d.runPingLoop(stop)
}

func (d *VirtualTun) runPingLoop(
	stop <-chan struct{},
) {
	defer d.pingLoopWg.Done()

	defer func() {
		if recovered := recover(); recovered != nil {
			Log.Error(
				"Ping loop panicked",
				"recover",
				recovered,
			)

			d.stopPingWorkers()
		}
	}()

	d.initPingWorkers()

	d.pingIPs()

	interval := time.Duration(
		d.Conf.CheckAliveInterval,
	) * time.Second

	if interval <= 0 {
		interval = 5 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
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

	stop := d.pingStop

	if stop == nil {
		return
	}

	close(stop)
	d.pingStop = nil

	// Не разрешаем StartPingIPs() запустить новый
	// ping loop до полного завершения старого.
	d.pingLoopWg.Wait()
}
