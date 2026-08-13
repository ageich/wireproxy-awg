```markdown
# wireproxy-awg

[![ISC licensed](https://img.shields.io/badge/license-ISC-blue)](./LICENSE)
[![Build status](https://github.com/ageich/wireproxy-awg/actions/workflows/build.yml/badge.svg)](https://github.com/ageich/wireproxy-awg/actions)
[![Documentation](https://img.shields.io/badge/godoc-wireproxy--awg-blue)](https://pkg.go.dev/github.com/ageich/wireproxy-awg)
[![GitHub Downloads](https://img.shields.io/github/downloads/ageich/wireproxy-awg/total.svg)](https://github.com/ageich/wireproxy-awg/releases)

Совместимый с AmneziaWG клиент WireGuard, который представляет себя как socks5/http прокси или туннель. Форк от [wireproxy](https://github.com/windtf/wireproxy).

## Что это такое

`wireproxy` — это полностью пользовательское приложение, которое подключается к пиру WireGuard и предоставляет socks5/http прокси или туннели на вашей машине. Это может быть полезно, если вам нужно подключиться к определённым сайтам через пир WireGuard, но вы не хотите настраивать новый сетевой интерфейс.

## Зачем это может понадобиться

- Вы хотите использовать WireGuard как способ проксирования некоторого трафика.
- Вам не нужны права root для настройки WireGuard.

В данный момент я запускаю wireproxy, подключённый к серверу WireGuard в другой стране, и настроил браузер так, чтобы он использовал wireproxy для определённых сайтов. Это удобно, поскольку wireproxy полностью изолирован от моих сетевых интерфейсов, и мне не нужны права root для настройки чего-либо.

Пользователям, которым нужно нечто подобное для Amnezia VPN, можно использовать [этот форк](https://github.com/ageich/wireproxy-awg).

## Возможности

- TCP-статическая маршрутизация для клиента и сервера
- SOCKS5/HTTP прокси (поддерживается только CONNECT)

## Планы

- Поддержка UDP в SOCKS5
- UDP-статическая маршрутизация

## Использование

```bash
./wireproxy [-h|--help] [-c|--config "<значение>"] [-s|--silent]
            [-d|--daemon] [-i|--info "<значение>"] [-v|--version]
            [-n|--configtest] [--max-memory "<значение>"]
```

```bash
использование: wireproxy [-h|--help] [-c|--config "<значение>"] [-s|--silent]
                         [-d|--daemon] [-i|--info "<значение>"] [-v|--version]
                         [-n|--configtest] [--max-memory "<значение>"]

                         Пользовательский клиент wireguard для проксирования

Аргументы:

  -h  --help         Показать справку
  -c  --config       Путь к файлу конфигурации
                     Пути по умолчанию: /etc/wireproxy/wireproxy.conf, $HOME/.config/wireproxy.conf
  -s  --silent       Тихий режим (без логов)
  -d  --daemon       Запустить wireproxy в фоновом режиме
  -i  --info         Указать адрес и порт для отображения статуса здоровья
  -v  --version      Показать версию
  -n  --configtest   Режим проверки конфигурации. Только проверить корректность файла конфигурации.
  --max-memory       Максимальный лимит потребления памяти (например, 600, 600MB, 1GiB).
                     Также может быть задан через переменную окружения GOMEMLIMIT (поддерживаются суффиксы: MiB, GiB, GB, KiB).
```

**Примеры ограничения памяти:**

```bash
# через аргумент командной строки (значение в мегабайтах)
./wireproxy --max-memory 600 -c config.conf

# через переменную окружения (с суффиксами)
export GOMEMLIMIT=600MiB   # или 1GiB, 2GB, 1024KiB и т.д.
./wireproxy -c config.conf
```

> Примечание: переменная `GOMEMLIMIT` имеет приоритет над `--max-memory`, если заданы обе.

## Инструкция по сборке

```bash
git clone https://github.com/ageich/wireproxy-awg
cd wireproxy-awg
make
```

## Установка

```bash
go install github.com/ageich/wireproxy-awg/cmd/wireproxy@latest
```

## Использование с VPN

Инструкции по использованию wireproxy с контейнерами Firefox и автозапуском на MacOS можно найти [здесь](/UseWithVPN.md).

## Пример конфигурационного файла

```ini
# Конфигурации [Interface] и [Peer] имеют ту же семантику и значение,
# что и конфигурация wg-quick. Чтобы понять эти поля, обратитесь к:
# https://wiki.archlinux.org/title/WireGuard#Persistent_configuration
# https://www.wireguard.com/#simple-network-interface
[Interface]
Address = 10.200.200.2/32 # Подсеть должна быть /32 и /128 для IPv4 и IPv6 соответственно
# MTU = 1420 (опционально)
PrivateKey = uCTIK+56CPyCvwJxmU5dBfuyJvPuSXAq1FzHdnIxe1Q=
# PrivateKey = $MY_WIREGUARD_PRIVATE_KEY # Альтернативно, можно ссылаться на переменные окружения
DNS = 10.200.200.1

[Peer]
PublicKey = QP+A67Z2UBrMgvNIdHv8gPel5URWNLS4B3ZQ2hQIZlg=
# PresharedKey = UItQuvLsyh50ucXHfjF0bbR4IIpVBd74lwKc8uIPXXs= (опционально)
Endpoint = my.ddns.example.com:51820
# PersistentKeepalive = 25 (опционально)

# TCPClientTunnel — туннель, слушающий на вашей машине,
# и перенаправляющий весь полученный TCP-трафик на указанную цель через wireguard.
# Поток:
# <приложение в вашей сети> --> localhost:25565 --(wireguard)--> play.cubecraft.net:25565
[TCPClientTunnel]
BindAddress = 127.0.0.1:25565
Target = play.cubecraft.net:25565

# TCPServerTunnel — туннель, слушающий на wireguard,
# и перенаправляющий весь полученный TCP-трафик на указанную цель через локальную сеть.
# Поток:
# <приложение в вашей сети wireguard> --(wireguard)--> 172.16.31.2:3422 --> localhost:25545
[TCPServerTunnel]
ListenPort = 3422
Target = localhost:25545

# STDIOTunnel — туннель, соединяющий стандартный ввод и вывод процесса wireproxy
# с указанной TCP-целью через wireguard.
# Это особенно полезно для использования wireproxy как параметра ProxyCommand в openssh.
# Например:
#    ssh -o ProxyCommand='wireproxy -c myconfig.conf' ssh.myserver.net
# Поток:
# Конвейерная команда -->(wireguard)--> ssh.myserver.net:22
[STDIOTunnel]
Target = ssh.myserver.net:22

# Socks5 создаёт socks5-прокси в вашей сети, и весь трафик будет направляться через wireguard.
[Socks5]
BindAddress = 127.0.0.1:25344

# Параметры аутентификации Socks5, указание имени пользователя и пароля включает аутентификацию прокси.
#Username = ...
# Избегайте пробелов в поле пароля
#Password = ...

# http создаёт http-прокси в вашей сети, и весь трафик будет направляться через wireguard.
[http]
BindAddress = 127.0.0.1:25345

# Параметры аутентификации HTTP, указание имени пользователя и пароля включает аутентификацию прокси.
#Username = ...
#Password = ...

# Указание сертификата и ключа включает HTTPS
#CertFile = ...
#KeyFile = ...
```

Альтернативно, если у вас уже есть конфигурация wireguard, вы можете импортировать её в файл конфигурации wireproxy следующим образом:

```ini
WGConfig = <путь к конфигурации wireguard>

# Та же семантика, что и выше
[TCPClientTunnel]
...

[TCPServerTunnel]
...

[Socks5]
...
```

Поддержка нескольких пиров также реализована. Необходимо указать `AllowedIPs`, чтобы wireproxy знал, какому пиру перенаправлять трафик.

```ini
[Interface]
Address = 10.254.254.40/32
PrivateKey = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=

[Peer]
Endpoint = 192.168.0.204:51820
PublicKey = YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY=
AllowedIPs = 10.254.254.100/32
PersistentKeepalive = 25

[Peer]
PublicKey = ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ=
AllowedIPs = 10.254.254.1/32, fdee:1337:c000:d00d::1/128
Endpoint = 172.16.0.185:44044
PersistentKeepalive = 25


[TCPServerTunnel]
ListenPort = 5000
Target = service-one.servicenet:5000

[TCPServerTunnel]
ListenPort = 5001
Target = service-two.servicenet:5001

[TCPServerTunnel]
ListenPort = 5080
Target = service-three.servicenet:80

[UDPProxyTunnel]
BindAddress = 127.0.0.1:53
Target = 1.1.1.1:53
InactivityTimeout = 30 # Если установить 0, таймаут никогда не наступит

[Resolve]
# Установка стратегии разрешения DNS
# `ipv4`: Приоритет A-записей.
# `ipv6`: Приоритет AAAA-записей.
# `auto` (по умолчанию): Если интерфейс WireGuard имеет только IPv4-адрес, эквивалентно `ipv4`, иначе `ipv6`.
ResolveStrategy = auto 
```

Wireproxy также может разрешать пирам подключаться к нему:

```ini
[Interface]
ListenPort = 5400
...

[Peer]
PublicKey = YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY=
AllowedIPs = 10.254.254.100/32
# Обратите внимание: здесь нет Endpoint.
```

## Эндпоинт здоровья

Wireproxy поддерживает публикацию эндпоинта для целей мониторинга.
Аргумент `--info/-i` указывает адрес и порт (например, `localhost:9080`), который открывает HTTP-сервер, предоставляющий метрики состояния сервера.

В настоящее время реализованы два эндпоинта:

`/metrics`: Предоставляет информацию о демоне wireguard, аналогичную выводу `wg show`. [Пример](https://www.wireguard.com/xplatform/#example-dialog) ответа.

`/readyz`: Отвечает JSON с временем последнего получения pong от IP-адресов, указанных в `CheckAlive`. Если `CheckAlive` установлен, через wireguard отправляется ping на адреса из `CheckAlive` каждые `CheckAliveInterval` секунд (по умолчанию 5). Если pong не был получен от одного из адресов в течение последних `CheckAliveInterval` секунд (+2 секунды для учёта задержки), то ответ будет 503, иначе 200.

Например:

```ini
[Interface]
PrivateKey = censored
Address = 10.2.0.2/32
DNS = 10.2.0.1
CheckAlive = 1.1.1.1, 3.3.3.3
CheckAliveInterval = 3

[Peer]
PublicKey = censored
AllowedIPs = 0.0.0.0/0
Endpoint = 149.34.244.174:51820

[Socks5]
BindAddress = 127.0.0.1:25344
```

`/readyz` ответит:

```text
< HTTP/1.1 503 Service Unavailable
< Date: Thu, 11 Apr 2024 00:54:59 GMT
< Content-Length: 35
< Content-Type: text/plain; charset=utf-8
<
{"1.1.1.1":1712796899,"3.3.3.3":0}
```

А для:

```ini
[Interface]
PrivateKey = censored
Address = 10.2.0.2/32
DNS = 10.2.0.1
CheckAlive = 1.1.1.1
```

`/readyz` ответит:

```text
< HTTP/1.1 200 OK
< Date: Thu, 11 Apr 2024 00:56:21 GMT
< Content-Length: 23
< Content-Type: text/plain; charset=utf-8
<
{"1.1.1.1":1712796979}
```

Если `CheckAlive` не задан, ответом будет пустой JSON-объект с кодом 200.

Пир, которому направляется ICMP-пакет ping, зависит от `AllowedIPs`, установленных для каждого пира.

# Загрузки

[![GitHub Downloads](https://img.shields.io/github/downloads/ageich/wireproxy-awg/total.svg)](https://github.com/ageich/wireproxy-awg/releases)
```
