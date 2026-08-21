package wireproxy

import (
	"errors"
	"strings"

	"github.com/go-ini/ini"
)

func ParsePeers(
	cfg *ini.File,
	peers *[]PeerConfig,
) error {
	sections, err :=
		cfg.SectionsByName("Peer")

	if len(sections) < 1 || err != nil {
		return errors.New(
			"at least one [Peer] is expected",
		)
	}

	for _, section := range sections {
		peer := PeerConfig{
			PreSharedKey:
				"0000000000000000000000000000000000000000000000000000000000000000",

			KeepAlive: 0,
		}

		decoded, err :=
			parseBase64KeyToHex(
				section,
				"PublicKey",
			)
		if err != nil {
			return err
		}

		peer.PublicKey = decoded

		if sectionKey, err :=
			section.GetKey("PreSharedKey"); err == nil {

			value, err :=
				encodeBase64ToHex(
					sectionKey.String(),
				)
			if err != nil {
				return err
			}

			peer.PreSharedKey = value
		}

		if sectionKey, err :=
			section.GetKey("Endpoint"); err == nil {

			value := sectionKey.String()

			decoded, err =
				resolveIPPAndPort(
					strings.ToLower(value),
				)
			if err != nil {
				return err
			}

			peer.Endpoint = &decoded
		}

		if sectionKey, err :=
			section.GetKey(
				"PersistentKeepalive",
			); err == nil {

			value, err :=
				sectionKey.Int()
			if err != nil {
				return err
			}

			peer.KeepAlive = value
		}

		peer.AllowedIPs, err =
			parseAllowedIPs(section)

		if err != nil {
			return err
		}

		*peers = append(
			*peers,
			peer,
		)
	}

	return nil
}
