package wireproxy

import (
	"errors"

	"github.com/go-ini/ini"
)

func ParseInterface(
	cfg *ini.File,
	device *DeviceConfig,
) error {
	sections, err :=
		cfg.SectionsByName("Interface")

	if len(sections) != 1 || err != nil {
		return errors.New(
			"one and only one [Interface] is expected",
		)
	}

	section := sections[0]

	address, err :=
		parseCIDRNetIP(
			section,
			"Address",
		)
	if err != nil {
		return err
	}

	device.Endpoint = address

	privKey, err :=
		parseBase64KeyToHex(
			section,
			"PrivateKey",
		)
	if err != nil {
		return err
	}

	device.SecretKey = privKey

	dns, err :=
		parseNetIP(
			section,
			"DNS",
		)
	if err != nil {
		return err
	}

	device.DNS = dns

	if sectionKey, err :=
		section.GetKey("MTU"); err == nil {

		value, err :=
			sectionKey.Int()
		if err != nil {
			return err
		}

		device.MTU = value
	}

	if sectionKey, err :=
		section.GetKey("ListenPort"); err == nil {

		value, err :=
			sectionKey.Int()
		if err != nil {
			return err
		}

		device.ListenPort = &value
	}

	checkAlive, err :=
		parseNetIP(
			section,
			"CheckAlive",
		)
	if err != nil {
		return err
	}

	device.CheckAlive = checkAlive
	device.CheckAliveInterval = 5

	if sectionKey, err :=
		section.GetKey(
			"CheckAliveInterval",
		); err == nil {

		value, err :=
			sectionKey.Int()
		if err != nil {
			return err
		}

		if len(checkAlive) == 0 {
			return errors.New(
				"CheckAliveInterval is only valid when CheckAlive is set",
			)
		}

		device.CheckAliveInterval = value
	}

	aSecConfig, err :=
		ParseASecConfig(section)
	if err != nil {
		return err
	}

	device.ASecConfig = aSecConfig

	return nil
}
