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
