package wireproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
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

	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

// ---------- Глобальные оптимизации ----------

var defaultDialer = &net.Dialer{
	Timeout:   DialTimeout,
	KeepAlive: 30 * time.Second,
}

// Оставляем 64 KiB.
// Pool используется самим SOCKS5 для повторного использования
// буферов передачи.
var socksPool = bufferpool.NewPool(64 * 1024)

// Ограничивает только установление новых TCP-соединений:
//
//	resolve DNS + Dial
//
// После успешного Dial semaphore освобождается.
// Длительные TCP-соединения semaphore НЕ занимают.
var tcpSemaphore = make(
	chan struct{},
	runtime.GOMAXPROCS(0)*256,
)

// ---------- ICMP read buffer pool ----------

var icmpReadPool = sync.Pool{
	New: func() any {
		b := make([]byte, 1500)
		return &b
	},
}

// ---------- ICMP sequence ----------

var pingSeq uint32

// ---------- Half-close ----------

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

type timeoutConn struct {
	net.Conn

	idle          time.Duration
	refreshBefore int64
	idleNS        int64

	readDeadline  atomic.Int64
	writeDeadline atomic.Int64
}

func newTimeoutConn(
	conn net.Conn,
	idle time.Duration,
) *timeoutConn {
	idleNS := idle.Nanoseconds()

	refreshBefore := idleNS / 10
	if refreshBefore <= 0 {
		refreshBefore = int64(time.Nanosecond)
	}

	return &timeoutConn{
		Conn:          conn,
		idle:          idle,
		refreshBefore: refreshBefore,
		idleNS:        idleNS,
	}
}

func (c *timeoutConn) refreshReadDeadline(nowUnix int64) {
	if c.idleNS <= 0 {
		return
	}

	deadline := c.readDeadline.Load()

	if deadline != 0 &&
		nowUnix < deadline-c.refreshBefore {
		return
	}

	newDeadlineUnix := nowUnix + c.idleNS

	if c.readDeadline.CompareAndSwap(
		deadline,
		newDeadlineUnix,
	) {
		_ = c.Conn.SetReadDeadline(
			time.Unix(0, newDeadlineUnix),
		)
	}
}

func (c *timeoutConn) refreshWriteDeadline(nowUnix int64) {
	if c.idleNS <= 0 {
		return
	}

	deadline := c.writeDeadline.Load()

	if deadline != 0 &&
		nowUnix < deadline-c.refreshBefore {
		return
	}

	newDeadlineUnix := nowUnix + c.idleNS

	if c.writeDeadline.CompareAndSwap(
		deadline,
		newDeadlineUnix,
	) {
		_ = c.Conn.SetWriteDeadline(
			time.Unix(0, newDeadlineUnix),
		)
	}
}

func (c *timeoutConn) Read(p []byte) (int, error) {
	c.refreshReadDeadline(
		time.Now().UnixNano(),
	)

	return c.Conn.Read(p)
}

func (c *timeoutConn) Write(p []byte) (int, error) {
	c.refreshWriteDeadline(
		time.Now().UnixNano(),
	)

	return c.Conn.Write(p)
}

func (c *timeoutConn) Close() error {
	return c.Conn.Close()
}

func (c *timeoutConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}

	return errHalfCloseUnsupported
}

func (c *timeoutConn) CloseRead() error {
	if cr, ok := c.Conn.(closeReader); ok {
		return cr.CloseRead()
	}

	return errHalfCloseUnsupported
}

// ---------- Dial ----------

func dialWithTimeout(
	ctx context.Context,
	network string,
	addr string,
	vt *VirtualTun,
) (net.Conn, error) {
	if vt == nil || vt.Tnet == nil {
		return nil, errors.New(
			"virtual tun is not initialized",
		)
	}

	conn, err := vt.Tnet.DialContext(
		ctx,
		network,
		addr,
	)
	if err != nil {
		return nil, err
	}

	return newTimeoutConn(
		conn,
		IdleTimeout,
	), nil
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

	return newTimeoutConn(
		conn,
		l.idle,
	), nil
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

	pingMu             sync.Mutex
	pingJobs           chan pingJob
	pingWorkers        sync.WaitGroup
	pingCtx            context.Context
	pingCancel         context.CancelFunc
	pingWorkersStarted bool
}

type pingJob struct {
	addr netip.Addr
	seq  uint16
	ts   uint64
}

// ---------- RoutineSpawner ----------

type RoutineSpawner interface {
	SpawnRoutine(ctx context.Context, vt *VirtualTun) error
}

type addressPort struct {
	address string
	port    uint16
}

// ---------- DNS / address helpers ----------

func (d *VirtualTun) LookupAddr(
	ctx context.Context,
	name string,
) ([]string, error) {
	if d == nil {
		return nil, errors.New(
			"virtual tun is nil",
		)
	}

	if d.SystemDNS {
		return net.DefaultResolver.LookupHost(
			ctx,
			name,
		)
	}

	if d.Tnet == nil {
		return nil, errors.New(
			"network stack is nil",
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
	addrs, err := d.LookupAddr(
		ctx,
		name,
	)
	if err != nil {
		return nil, err
	}

	if len(addrs) == 0 {
		return nil, errors.New(
			"no address found for: " + name,
		)
	}

	if len(addrs) > 1 {
		rand.Shuffle(
			len(addrs),
			func(i, j int) {
				addrs[i], addrs[j] =
					addrs[j], addrs[i]
			},
		)
	}

	var lastErr error

	for _, saddr := range addrs {
		addr, err := netip.ParseAddr(saddr)
		if err == nil {
			return &addr, nil
		}

		lastErr = err
	}

	if lastErr == nil {
		lastErr = errors.New(
			"invalid DNS result",
		)
	}

	return nil, lastErr
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
	name, sport, err := net.SplitHostPort(
		endpoint,
	)
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
	if endpoint == nil {
		return nil, errors.New(
			"endpoint is nil",
		)
	}

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

// ---------- SOCKS5 ----------

func (config *Socks5Config) SpawnRoutine(
	ctx context.Context,
	vt *VirtualTun,
) error {
	if config == nil {
		return errors.New(
			"SOCKS5 config is nil",
		)
	}

	if vt == nil || vt.Tnet == nil {
		return errors.New(
			"virtual tun is not initialized",
		)
	}

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

	server := socks5.NewServer(
		socks5.WithDial(dial),
		socks5.WithResolver(resolver),
		socks5.WithAuthMethods(authMethods),
		socks5.WithBufferPool(socksPool),
		socks5.WithUDPReadTimeout(IdleTimeout),
	)

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

// ---------- HTTP ----------

func (config *HTTPConfig) SpawnRoutine(
	ctx context.Context,
	vt *VirtualTun,
) error {
	if config == nil {
		return errors.New(
			"HTTP config is nil",
		)
	}

	if vt == nil || vt.Tnet == nil {
		return errors.New(
			"virtual tun is not initialized",
		)
	}

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

// ---------- TCP Client ----------

func (conf *TCPClientTunnelConfig) SpawnRoutine(
	ctx context.Context,
	vt *VirtualTun,
) error {
	if conf == nil {
		return errors.New(
			"TCP client config is nil",
		)
	}

	if vt == nil || vt.Tnet == nil {
		return errors.New(
			"virtual tun is not initialized",
		)
	}

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

// ---------- STDIO ----------

func (conf *STDIOTunnelConfig) SpawnRoutine(
	ctx context.Context,
	vt *VirtualTun,
) error {
	if conf == nil {
		return errors.New(
			"STDIO config is nil",
		)
	}

	if vt == nil || vt.Tnet == nil {
		return errors.New(
			"virtual tun is not initialized",
		)
	}

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

// ---------- TCP Server ----------

func (conf *TCPServerTunnelConfig) SpawnRoutine(
	ctx context.Context,
	vt *VirtualTun,
) error {
	if conf == nil {
		return errors.New(
			"TCP server config is nil",
		)
	}

	if vt == nil || vt.Tnet == nil {
		return errors.New(
			"virtual tun is not initialized",
		)
	}

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

	if conf.ListenPort < 0 ||
		conf.ListenPort > 65535 {
		return fmt.Errorf(
			"invalid listen port: %d",
			conf.ListenPort,
		)
	}

	server, err := vt.Tnet.ListenTCP(
		&net.TCPAddr{
			Port: conf.ListenPort,
		},
	)
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

// ---------- UDP ----------

func (conf *UDPProxyTunnelConfig) SpawnRoutine(
	ctx context.Context,
	vt *VirtualTun,
) error {
	if conf == nil {
		return errors.New(
			"UDP proxy config is nil",
		)
	}

	if vt == nil || vt.Tnet == nil {
		return errors.New(
			"virtual tun is not initialized",
		)
	}

	return conf.SpawnUDPProxy(
		ctx,
		vt,
	)
}

// ---------- Bidirectional copy ----------

func closeWriteOrClose(conn net.Conn) {
	if conn == nil {
		return
	}

	if cw, ok := conn.(closeWriter); ok {
		if err := cw.CloseWrite(); err == nil {
			return
		}
	}

	_ = conn.Close()
}

func closeReadOrClose(conn net.Conn) {
	if conn == nil {
		return
	}

	if cr, ok := conn.(closeReader); ok {
		if err := cr.CloseRead(); err == nil {
			return
		}
	}

	_ = conn.Close()
}

func copyBidirectional(
	a,
	b net.Conn,
) {
	if a == nil || b == nil {
		if a != nil {
			_ = a.Close()
		}

		if b != nil {
			_ = b.Close()
		}

		return
	}

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

// ---------- TCP forwards ----------

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

	if conn == nil {
		return
	}

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

	if conn == nil {
		return
	}

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

// ---------- STDIO forward ----------

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

	stdout := os.Stdout

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

	case <-done:
		_ = sconn.Close()
	}

	wg.Wait()
}

// ---------- ICMP worker pool ----------

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

	jobs := make(
		chan pingJob,
		queueSize,
	)

	d.pingCtx = pingCtx
	d.pingCancel = cancel
	d.pingJobs = jobs
	d.pingWorkersStarted = true

	for i := 0; i < workers; i++ {
		d.pingWorkers.Add(1)

		go func(
			jobs <-chan pingJob,
			ctx context.Context,
		) {
			defer d.pingWorkers.Done()

			for {
				select {
				case <-ctx.Done():
					return

				case job, ok := <-jobs:
					if !ok {
						return
					}

					d.doPing(
						job.addr,
						job.seq,
						job.ts,
					)
				}
			}
		}(
			jobs,
			pingCtx,
		)
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

// ---------- ICMP ----------

func (d *VirtualTun) doPing(
	addr netip.Addr,
	seq uint16,
	ts uint64,
) {
	if d == nil ||
		d.Tnet == nil ||
		d.Conf == nil {
		return
	}

	socket, err := d.Tnet.Dial(
		"ping",
		addr.String(),
	)
	if err != nil {
		return
	}

	defer socket.Close()

	var packetBuf [24]byte
	var proto int

	if addr.Is4() {
		proto = 1

		packetBuf[0] = 8
		packetBuf[1] = 0

		binary.BigEndian.PutUint16(
			packetBuf[4:6],
			0,
		)

		binary.BigEndian.PutUint16(
			packetBuf[6:8],
			seq,
		)

		binary.BigEndian.PutUint32(
			packetBuf[8:12],
			uint32(seq),
		)

		binary.BigEndian.PutUint64(
			packetBuf[12:20],
			ts,
		)

		cs := checksum(
			packetBuf[:20],
		)

		binary.BigEndian.PutUint16(
			packetBuf[2:4],
			cs,
		)

	} else if addr.Is6() {
		proto = 58

		packetBuf[0] = 128
		packetBuf[1] = 0

		binary.BigEndian.PutUint16(
			packetBuf[4:6],
			0,
		)

		binary.BigEndian.PutUint16(
			packetBuf[6:8],
			seq,
		)

		binary.BigEndian.PutUint32(
			packetBuf[8:12],
			uint32(seq),
		)

		binary.BigEndian.PutUint64(
			packetBuf[12:20],
			ts,
		)

	} else {
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

	if _, err = socket.Write(
		packetBuf[:20],
	); err != nil {
		return
	}

	bufPtr := icmpReadPool.Get().(*[]byte)
	readBuf := *bufPtr

	defer icmpReadPool.Put(bufPtr)

	n, err := socket.Read(readBuf)
	if err != nil ||
		n <= 0 ||
		n > len(readBuf) {
		return
	}

	replyPacket, err := icmp.ParseMessage(
		proto,
		readBuf[:n],
	)
	if err != nil {
		return
	}

	if addr.Is4() {
		replyPing, ok := replyPacket.Body.(*icmp.Echo)
		if !ok {
			return
		}

		if replyPing.Seq != int(seq) {
			return
		}
	} else {
		replyPing, ok := replyPacket.Body.(*icmp.RawBody)
		if !ok || len(replyPing.Data) < 4 {
			return
		}

		rxSeq := binary.BigEndian.Uint16(
			replyPing.Data[2:4],
		)

		if rxSeq != seq {
			return
		}
	}

	if d.PingRecord != nil {
		d.PingRecord.Add(
			addr.String(),
			uint64(time.Now().Unix()),
		)
	}
}

func checksum(b []byte) uint16 {
	var sum uint32

	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(
			binary.BigEndian.Uint16(
				b[i : i+2],
			),
		)
	}

	if len(b)&1 != 0 {
		sum += uint32(
			b[len(b)-1],
		) << 8
	}

	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) +
			(sum >> 16)
	}

	return ^uint16(sum)
}

func (d *VirtualTun) pingIPs() {
	if d == nil ||
		d.Conf == nil {
		return
	}

	d.pingMu.Lock()

	jobs := d.pingJobs
	pingCtx := d.pingCtx

	d.pingMu.Unlock()

	if jobs == nil ||
		pingCtx == nil {
		return
	}

	select {
	case <-pingCtx.Done():
		return

	default:
	}

	seq := uint16(
		atomic.AddUint32(
			&pingSeq,
			1,
		),
	)

	ts := uint64(
		time.Now().UnixNano(),
	)

	for _, addr := range d.Conf.CheckAlive {
		select {
		case <-pingCtx.Done():
			return

		case jobs <- pingJob{
			addr: addr,
			seq:  seq,
			ts:   ts,
		}:
		}
	}
}

// ---------- HTTP ----------

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

		interval := 5 * time.Second

		if d.Conf != nil &&
			d.Conf.CheckAliveInterval > 0 {
			interval =
				time.Duration(
					d.Conf.CheckAliveInterval,
				) * time.Second
		}

		ttl := interval + 2*time.Second

		ok := true

		if d.Conf != nil {
			for _, addr := range d.Conf.CheckAlive {
				val, okRec := d.PingRecord.Get(
					addr.String(),
				)

				if !okRec ||
					val == 0 ||
					now.Sub(
						time.Unix(
							int64(val),
							0,
						),
					) > ttl {
					ok = false
					break
				}
			}
		}

		if ok {
			w.WriteHeader(
				http.StatusOK,
			)
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

		buf.Grow(len(get))

		data := []byte(get)

		for len(data) > 0 {
			idx := bytes.IndexByte(
				data,
				'\n',
			)

			var line []byte

			if idx >= 0 {
				line = data[:idx]
				data = data[idx+1:]
			} else {
				line = data
				data = nil
			}

			if len(line) == 0 {
				continue
			}

			eqIdx := bytes.IndexByte(
				line,
				'=',
			)

			if eqIdx < 0 {
				buf.Write(line)
				buf.WriteByte('\n')
				continue
			}

			key := line[:eqIdx]

			if bytes.Equal(
				key,
				[]byte("private_key"),
			) ||
				bytes.Equal(
					key,
					[]byte("preshared_key"),
				) {
				buf.Write(key)
				buf.WriteString(
					"=REDACTED\n",
				)

				continue
			}

			buf.Write(line)
			buf.WriteByte('\n')
		}

		w.WriteHeader(
			http.StatusOK,
		)

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

	if d.pingStop != nil ||
		d.Conf == nil {
		return
	}

	ttl := time.Duration(
		d.Conf.CheckAliveInterval+2,
	) * time.Second

	if ttl <= 0 {
		ttl = 7 * time.Second
	}

	cacheSize := d.DnsCacheSize

	if cacheSize < len(
		d.Conf.CheckAlive,
	) {
		cacheSize = len(
			d.Conf.CheckAlive,
		)
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
		key := addr.String()

		if _, ok := d.PingRecord.Get(key); !ok {
			d.PingRecord.Add(
				key,
				0,
			)
		}
	}

	stop := make(chan struct{})

	d.pingStop = stop

	d.pingLoopWg.Add(1)

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

			// Не брать pingStopMu здесь:
			// StopPingIPs может держать его во время Wait().
			d.stopPingWorkers()
		}
	}()

	d.initPingWorkers()
	d.pingIPs()

	interval := 5 * time.Second

	if d.Conf != nil &&
		d.Conf.CheckAliveInterval > 0 {
		interval =
			time.Duration(
				d.Conf.CheckAliveInterval,
			) * time.Second
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

	// runPingLoop не берет pingStopMu,
	// поэтому Wait безопасен.
	d.pingLoopWg.Wait()
}
