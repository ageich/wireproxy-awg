package main

import "os"

var defaultConfigPaths = []string{
	"/etc/wireproxy/wireproxy.conf",
	os.Getenv("HOME") + "/.config/wireproxy.conf",
}

func configFilePath() (string, bool) {
	for _, path := range defaultConfigPaths {
		if path == "" {
			continue
		}

		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}

	return "", false
}
