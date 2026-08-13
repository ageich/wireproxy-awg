---

```markdown
[![ISC licensed](https://img.shields.io/badge/license-ISC-blue)](./LICENSE)
[![Build status](https://github.com/ageich/wireproxy-awg/actions/workflows/build.yml/badge.svg)](https://github.com/ageich/wireproxy-awg/actions)
[![Documentation](https://img.shields.io/badge/godoc-wireproxy--awg-blue)](https://pkg.go.dev/github.com/ageich/wireproxy-awg)
[![GitHub Downloads](https://img.shields.io/github/downloads/ageich/wireproxy-awg/total.svg)](https://github.com/ageich/wireproxy-awg/releases)

# wireproxy-awg

Совместимый с AmneziaWG клиент WireGuard, представляющий себя как socks5/http прокси или туннель.  
Форк от [wireproxy](https://github.com/windtf/wireproxy).

## Что это такое

`wireproxy` — полностью пользовательское приложение, которое подключается к пиру WireGuard и предоставляет socks5/http прокси или туннели на вашей машине.  
Полезно, если нужно подключиться к определённым сайтам через пир WireGuard, но нет желания настраивать новый сетевой интерфейс.

## Зачем это нужно

- Использовать WireGuard для проксирования части трафика.
- Не требовать прав root для настройки WireGuard.

Пользователям, которым нужно нечто подобное для Amnezia VPN, доступен [этот форк](https://github.com/ageich/wireproxy-awg).

## Возможности

- TCP-статическая маршрутизация для клиента и сервера.
- SOCKS5/HTTP прокси (поддерживается только CONNECT).

## Планы

- Поддержка UDP в SOCKS5.
- UDP-статическая маршрутизация.

## Использование

```bash
./wireproxy [-h|--help] [-c|--config "<значение>"] \
            [-s|--silent] [-d|--daemon] [-i|--info "<значение>"] \
            [-v|--version] [-n|--configtest] [--max-memory "<значение>"]
```

```text
usage: wireproxy [-h|--help] [-c|--config "<значение>"] [-s|--silent]
                 [-d|--daemon] [-i|--info "<значение>"] [-v|--version]
                 [-n|--configtest] [--max-memory "<значение>"]
                 Пользовательский клиент wireguard для проксирования

Arguments:
  -h  --help         Показать справку
  -c  --config       Путь к файлу конфигурации
                     (по умолчанию: /etc/wireproxy/wireproxy.conf,
                      $HOME/.config/wireproxy.conf)
  -s  --silent       Тихий режим (без логов)
  -d  --daemon       Запустить в фоновом режиме
  -i  --info         Адрес:порт для статуса здоровья
  -v  --version      Показать версию
  -n  --configtest   Только проверить конфигурацию
  --max-memory       Лимит памяти (например, 600, 600MB, 1GiB)
                     Также можно задать через GOMEMLIMIT
                     (суффиксы: MiB, GiB, GB, KiB)
```

**Примеры ограничения памяти:**

```bash
# через аргумент командной строки (в мегабайтах)
./wireproxy --max-memory 600 -c config.conf

# через переменную окружения (с суффиксами)
export GOMEMLIMIT=600MiB   # или 1GiB, 2GB, 1024KiB
./wireproxy -c config.conf
```

> Примечание: `GOMEMLIMIT` имеет приоритет над `--max-memory`.

## Сборка

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

Инструкции по использованию с Firefox и автозапуском на MacOS: [UseWithVPN.md](/UseWithVPN.md).

## Пример конфигурации

```ini
[Interface]
Address = 10.200.200.2/32
PrivateKey = uCTIK+56CPyCvwJxmU5dBfuyJvPuSXAq1FzHdnIxe1Q=
DNS = 10.200.200.1

[Peer]
PublicKey = QP+A67Z2UBrMgvNIdHv8gPel5URWNLS4B3ZQ2hQIZlg=
Endpoint = my.ddns.example.com:51820

[TCPClientTunnel]
BindAddress = 127.0.0.1:25565
Target = play.cubecraft.net:25565

[TCPServerTunnel]
ListenPort = 3422
Target = localhost:25545

[STDIOTunnel]
Target = ssh.myserver.net:22

[Socks5]
BindAddress = 127.0.0.1:25344

[http]
BindAddress = 127.0.0.1:25345
```

Полный пример с комментариями: см. [README оригинального репозитория](https://github.com/windtf/wireproxy#sample-config-file).

## Эндпоинт здоровья

Аргумент `--info` открывает HTTP-сервер с двумя эндпоинтами:

- `/metrics` – информация о WireGuard (аналог `wg show`).
- `/readyz` – JSON с временем последнего ping/pong для адресов из `CheckAlive`.

Пример конфигурации с проверкой:

```ini
[Interface]
CheckAlive = 1.1.1.1, 3.3.3.3
CheckAliveInterval = 3
...
```

При недоступности одного из адресов `/readyz` вернёт 503.

# Загрузки

[![GitHub Downloads](https://img.shields.io/github/downloads/ageich/wireproxy-awg/total.svg)](https://github.com/ageich/wireproxy-awg/releases)
```

---
