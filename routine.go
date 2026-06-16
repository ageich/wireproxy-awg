package wireproxy

import (
	"bytes"
	"context"
	srand "crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
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

// errorLogger is the logger to print error message
var errorLogger = log.New(os.Stderr, "ERROR: ", log.LstdFlags)

// CredentialValidator stores the authentication data of a socks5 proxy
type CredentialValidator struct {
	username string
	password string
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
type RoutineSpawner interface {
	SpawnRoutine(vt *VirtualTun)
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
	Cache     *expirable.LRU[string, net.IP] // экспортируемое поле для тестов
}

// NewFixedResolver creates a new resolver with LRU cache and TTL expiration
func NewFixedResolver(tnet *netstack.Net, systemDNS bool, ttl time.Duration, cacheSize int) *fixedResolver {
	// Создаём LRU-кэш с заданным размером и TTL (удаление происходит автоматически)
	cache := expirable.NewLRU[string, net.IP](cacheSize, nil, ttl)
	return &fixedResolver{
		tnet:      tnet,
		systemDNS: systemDNS,
		Cache:     cache,
	}
}

// Resolve implements socks5.NameResolver
func (r *fixedResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	// Проверяем кэш
	if ip, ok := r.Cache.Get(name); ok {
		return ctx, ip, nil
	}

	// Если не найдено, выполняем резолвинг
	var ip net.IP
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

	// Сохраняем в кэш (при превышении лимита вытеснится самая старая запись)
	r.Cache.Add(name, ip)
	return ctx, ip, nil
}

// Stop is a no-op for compatibility (cleanup is handled automatically by expirable.LRU)
func (r *fixedResolver) Stop() {
	// Ничего не делаем, так как expirable.LRU самостоятельно управляет памятью
}

// ---------- End of DNS resolver ----------

// LookupAddr lookups a hostname.
// DNS traffic may or may not be routed depending on VirtualTun's setting
func (d VirtualTun) LookupAddr(ctx context.Context, name string) ([]string, error) {
	if d.SystemDNS {
		return net.DefaultResolver.LookupHost(ctx, name)
	}
	return d.Tnet.LookupContextHost(ctx, name)
}

// ResolveAddrWithContext resolves a hostname and returns an AddrPort.
// DNS traffic may or may not be routed depending on VirtualTun's setting
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
// DNS traffic may or may not be routed depending on VirtualTun's setting
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

// SpawnRoutine spawns a socks5 server with fixed DNS resolver (LRU cache)
func (config *Socks5Config) SpawnRoutine(vt *VirtualTun) {
	// Используем TTL 5 минут и размер кэша из vt.DnsCacheSize (по умолчанию 1000)
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

	if err := server.ListenAndServe("tcp", config.BindAddress); err != nil {
		log.Fatal(err)
	}
}

// SpawnRoutine spawns a http server.
func (config *HTTPConfig) SpawnRoutine(vt *VirtualTun) {
	server := &HTTPServer{
		config: config,
		dial:   vt.Tnet.Dial,
		auth:   CredentialValidator{config.Username, config.Password},
	}
	if config.Username != "" || config.Password != "" {
		server.authRequired = true
	}

	if err := server.ListenAndServe("tcp", config.BindAddress); err != nil {
		log.Fatal(err)
	}
}

// Valid checks the authentication data in CredentialValidator and compare them
// to username and password in constant time.
func (c CredentialValidator) Valid(username, password string) bool {
	u := subtle.ConstantTimeCompare([]byte(c.username), []byte(username))
	p := subtle.ConstantTimeCompare([]byte(c.password), []byte(password))
	return u&p == 1
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
func tcpClientForward(vt *VirtualTun, raddr *addressPort, conn net.Conn) {
	target, err := vt.resolveToAddrPort(raddr)
	if err != nil {
		errorLogger.Printf("TCP Server Tunnel to %s: %s\n", target, err.Error())
		return
	}

	tcpAddr := net.TCPAddrFromAddrPort(*target)

	sconn, err := vt.Tnet.DialTCP(tcpAddr)
	if err != nil {
		errorLogger.Printf("TCP Client Tunnel to %s: %s\n", target, err.Error())
		return
	}

	go connForward(sconn, conn)
	go connForward(conn, sconn)
}

// STDIOTcpForward starts a new connection via wireguard and forward traffic from `conn`
// Теперь принимает input и output файлы вместо глобальных.
func STDIOTcpForward(vt *VirtualTun, raddr *addressPort, input, output *os.File) {
	target, err := vt.resolveToAddrPort(raddr)
	if err != nil {
		errorLogger.Printf("Name resolution error for %s: %s\n", raddr.address, err.Error())
		return
	}

	tcpAddr := net.TCPAddrFromAddrPort(*target)
	sconn, err := vt.Tnet.DialTCP(tcpAddr)
	if err != nil {
		errorLogger.Printf("TCP Client Tunnel to %s (%s): %s\n", target, tcpAddr, err.Error())
		return
	}

	go connForward(input, sconn)
	go connForward(sconn, output)
}

// SpawnRoutine connects to the specified target and plumbs it to STDIN / STDOUT
func (conf *STDIOTunnelConfig) SpawnRoutine(vt *VirtualTun) {
	raddr, err := parseAddressPort(conf.Target)
	if err != nil {
		log.Fatal(err)
	}

	// Передаём input и output из конфига
	go STDIOTcpForward(vt, raddr, conf.Input, conf.Output)
}

// tcpServerForward starts a new connection locally and forward traffic from `conn`
func tcpServerForward(vt *VirtualTun, raddr *addressPort, conn net.Conn) {
	target, err := vt.resolveToAddrPort(raddr)
	if err != nil {
		errorLogger.Printf("TCP Server Tunnel to %s: %s\n", target, err.Error())
		return
	}

	tcpAddr := net.TCPAddrFromAddrPort(*target)

	sconn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		errorLogger.Printf("TCP Server Tunnel to %s: %s\n", target, err.Error())
		return
	}

	go connForward(sconn, conn)
	go connForward(conn, sconn)

}

// SpawnRoutine spawns a TCP server on wireguard which acts as a proxy to the specified target
func (conf *TCPServerTunnelConfig) SpawnRoutine(vt *VirtualTun) {
	raddr, err := parseAddressPort(conf.Target)
	if err != nil {
		log.Fatal(err)
	}

	addr := &net.TCPAddr{Port: conf.ListenPort}
	server, err := vt.Tnet.ListenTCP(addr)
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := server.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go tcpServerForward(vt, raddr, conn)
	}
}

// ServeHTTP обрабатывает HTTP-запросы для метрик (health check / metrics).
// Использует LRU-кэш PingRecord для получения данных.
func (d VirtualTun) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Health metric request: %s\n", r.URL.Path)
	switch path.Clean(r.URL.Path) {
	case "/readyz":
		// Собираем данные из PingRecord
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
			// +2 seconds to account for the time it takes to ping the IP
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

				seq := binary.BigEndian.Uint16(replyPing.Data[2:4])
				pongBody := replyPing.Data[4:]
				if !bytes.Equal(pongBody, requestPing.Data) || int(seq) != requestPing.Seq {
					errorLogger.Printf("Failed to parse ping response from %s: invalid ping reply: %v\n", addr, replyPing)
					return
				}
			}

			// Сохраняем время успешного пинга в LRU-кэш (потокобезопасно)
			d.PingRecord.Add(addr.String(), uint64(time.Now().Unix()))
		}()
	}
}

// StartPingIPs starts a background goroutine that periodically pings all configured IPs.
// The goroutine can be stopped by calling StopPingIPs().
func (d *VirtualTun) StartPingIPs() {
	d.pingStopMu.Lock()
	defer d.pingStopMu.Unlock()

	// Инициализируем кэш нулевыми значениями для всех проверяемых адресов
	for _, addr := range d.Conf.CheckAlive {
		d.PingRecord.Add(addr.String(), 0)
	}

	// Если канал уже существует, значит горутина уже запущена
	if d.pingStop != nil {
		return
	}

	// Создаём новый канал и сохраняем его
	stopChan := make(chan struct{})
	d.pingStop = stopChan

	// Запускаем горутину с локальной переменной канала
	go func(stop <-chan struct{}) {
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
