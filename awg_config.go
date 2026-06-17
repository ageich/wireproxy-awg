package wireproxy

import (
	"errors"
	"strconv"
	"strings"

	"github.com/go-ini/ini"
)

type ASecConfigType struct {
	junkPacketCount               int
	junkPacketMinSize             int
	junkPacketMaxSize             int
	initPacketJunkSize            int
	responsePacketJunkSize        int
	cookieReplyPacketJunkSize     int
	transportPacketJunkSize       int
	initPacketMagicHeader         uint32
	initPacketMagicHeaderMax      uint32
	responsePacketMagicHeader     uint32
	responsePacketMagicHeaderMax  uint32
	underloadPacketMagicHeader    uint32
	underloadPacketMagicHeaderMax uint32
	transportPacketMagicHeader    uint32
	transportPacketMagicHeaderMax uint32
	hasJunkPacketCount            bool
	hasJunkPacketMinSize          bool
	hasJunkPacketMaxSize          bool
	hasInitPacketJunkSize         bool
	hasResponsePacketJunkSize     bool
	hasCookieReplyPacketJunkSize  bool
	hasTransportPacketJunkSize    bool
	hasInitPacketMagicHeader      bool
	hasResponsePacketMagicHeader  bool
	hasUnderloadPacketMagicHeader bool
	hasTransportPacketMagicHeader bool
	i1                            *string
	i2                            *string
	i3                            *string
	i4                            *string
	i5                            *string
}

// parseIntField парсит целочисленное поле и устанавливает флаг наличия.
func parseIntField(section *ini.Section, keyName string, config **ASecConfigType, setter func(*ASecConfigType, int), flagSetter func(*ASecConfigType, bool)) error {
	key, err := section.GetKey(keyName)
	if err != nil {
		return nil // ключ отсутствует — не ошибка
	}
	value, err := key.Int()
	if err != nil {
		return err
	}
	if *config == nil {
		*config = &ASecConfigType{}
	}
	setter(*config, value)
	flagSetter(*config, true)
	return nil
}

// parseMagicHeaderField парсит поле магического заголовка (интервал) и устанавливает флаг.
func parseMagicHeaderField(section *ini.Section, keyName string, config **ASecConfigType,
	minSetter func(*ASecConfigType, uint32), maxSetter func(*ASecConfigType, uint32), flagSetter func(*ASecConfigType, bool)) error {
	key, err := section.GetKey(keyName)
	if err != nil {
		return nil // ключ отсутствует — не ошибка
	}
	minVal, maxVal, err := parseMagicHeaderInterval(key.String())
	if err != nil {
		return err
	}
	if *config == nil {
		*config = &ASecConfigType{}
	}
	minSetter(*config, minVal)
	maxSetter(*config, maxVal)
	flagSetter(*config, true)
	return nil
}

// parseStringField парсит строковое поле и сохраняет указатель.
func parseStringField(section *ini.Section, keyName string, config **ASecConfigType, setter func(*ASecConfigType, *string)) error {
	key, err := section.GetKey(keyName)
	if err != nil {
		return nil // ключ отсутствует — не ошибка
	}
	value := key.String()
	if *config == nil {
		*config = &ASecConfigType{}
	}
	setter(*config, &value)
	return nil
}

// ParseASecConfig загружает и валидирует секцию AmneziaWG.
func ParseASecConfig(section *ini.Section) (*ASecConfigType, error) {
	var config *ASecConfigType

	// Целочисленные поля
	if err := parseIntField(section, "Jc", &config,
		func(c *ASecConfigType, v int) { c.junkPacketCount = v },
		func(c *ASecConfigType, b bool) { c.hasJunkPacketCount = b },
	); err != nil {
		return nil, err
	}

	if err := parseIntField(section, "Jmin", &config,
		func(c *ASecConfigType, v int) { c.junkPacketMinSize = v },
		func(c *ASecConfigType, b bool) { c.hasJunkPacketMinSize = b },
	); err != nil {
		return nil, err
	}

	if err := parseIntField(section, "Jmax", &config,
		func(c *ASecConfigType, v int) { c.junkPacketMaxSize = v },
		func(c *ASecConfigType, b bool) { c.hasJunkPacketMaxSize = b },
	); err != nil {
		return nil, err
	}

	if err := parseIntField(section, "S1", &config,
		func(c *ASecConfigType, v int) { c.initPacketJunkSize = v },
		func(c *ASecConfigType, b bool) { c.hasInitPacketJunkSize = b },
	); err != nil {
		return nil, err
	}

	if err := parseIntField(section, "S2", &config,
		func(c *ASecConfigType, v int) { c.responsePacketJunkSize = v },
		func(c *ASecConfigType, b bool) { c.hasResponsePacketJunkSize = b },
	); err != nil {
		return nil, err
	}

	if err := parseIntField(section, "S3", &config,
		func(c *ASecConfigType, v int) { c.cookieReplyPacketJunkSize = v },
		func(c *ASecConfigType, b bool) { c.hasCookieReplyPacketJunkSize = b },
	); err != nil {
		return nil, err
	}

	if err := parseIntField(section, "S4", &config,
		func(c *ASecConfigType, v int) { c.transportPacketJunkSize = v },
		func(c *ASecConfigType, b bool) { c.hasTransportPacketJunkSize = b },
	); err != nil {
		return nil, err
	}

	// Поля магических заголовков (интервалы)
	if err := parseMagicHeaderField(section, "H1", &config,
		func(c *ASecConfigType, v uint32) { c.initPacketMagicHeader = v },
		func(c *ASecConfigType, v uint32) { c.initPacketMagicHeaderMax = v },
		func(c *ASecConfigType, b bool) { c.hasInitPacketMagicHeader = b },
	); err != nil {
		return nil, err
	}

	if err := parseMagicHeaderField(section, "H2", &config,
		func(c *ASecConfigType, v uint32) { c.responsePacketMagicHeader = v },
		func(c *ASecConfigType, v uint32) { c.responsePacketMagicHeaderMax = v },
		func(c *ASecConfigType, b bool) { c.hasResponsePacketMagicHeader = b },
	); err != nil {
		return nil, err
	}

	if err := parseMagicHeaderField(section, "H3", &config,
		func(c *ASecConfigType, v uint32) { c.underloadPacketMagicHeader = v },
		func(c *ASecConfigType, v uint32) { c.underloadPacketMagicHeaderMax = v },
		func(c *ASecConfigType, b bool) { c.hasUnderloadPacketMagicHeader = b },
	); err != nil {
		return nil, err
	}

	if err := parseMagicHeaderField(section, "H4", &config,
		func(c *ASecConfigType, v uint32) { c.transportPacketMagicHeader = v },
		func(c *ASecConfigType, v uint32) { c.transportPacketMagicHeaderMax = v },
		func(c *ASecConfigType, b bool) { c.hasTransportPacketMagicHeader = b },
	); err != nil {
		return nil, err
	}

	// Строковые поля (I1-I5)
	if err := parseStringField(section, "I1", &config, func(c *ASecConfigType, v *string) { c.i1 = v }); err != nil {
		return nil, err
	}
	if err := parseStringField(section, "I2", &config, func(c *ASecConfigType, v *string) { c.i2 = v }); err != nil {
		return nil, err
	}
	if err := parseStringField(section, "I3", &config, func(c *ASecConfigType, v *string) { c.i3 = v }); err != nil {
		return nil, err
	}
	if err := parseStringField(section, "I4", &config, func(c *ASecConfigType, v *string) { c.i4 = v }); err != nil {
		return nil, err
	}
	if err := parseStringField(section, "I5", &config, func(c *ASecConfigType, v *string) { c.i5 = v }); err != nil {
		return nil, err
	}

	if err := ValidateASecConfig(config); err != nil {
		return nil, err
	}
	return config, nil
}

// ValidateASecConfig — без изменений (оставлен как был).
func ValidateASecConfig(config *ASecConfigType) error {
	if config == nil {
		return nil
	}
	if config.hasJunkPacketCount && (config.junkPacketCount < 1 || config.junkPacketCount > 128) {
		return errors.New("value of the Jc field must be within the range of 1 to 128")
	}
	if config.hasJunkPacketMinSize && config.hasJunkPacketMaxSize &&
		config.junkPacketMinSize > config.junkPacketMaxSize {
		return errors.New("value of the Jmin field must be less than or equal to Jmax field value")
	}
	if config.hasJunkPacketMaxSize && config.junkPacketMaxSize > 1280 {
		return errors.New("value of the Jmax field must be less than or equal 1280")
	}

	const (
		messageInitiationSize = 148
		messageResponseSize   = 92
		messageCookieReplySize = 64
		messageTransportSize  = 32
	)

	type packetSizeCheck struct {
		isSet bool
		size  int
	}

	packetSizes := []packetSizeCheck{
		{isSet: config.hasInitPacketJunkSize, size: messageInitiationSize + config.initPacketJunkSize},
		{isSet: config.hasResponsePacketJunkSize, size: messageResponseSize + config.responsePacketJunkSize},
		{isSet: config.hasCookieReplyPacketJunkSize, size: messageCookieReplySize + config.cookieReplyPacketJunkSize},
		{isSet: config.hasTransportPacketJunkSize, size: messageTransportSize + config.transportPacketJunkSize},
	}
	for i := 0; i < len(packetSizes); i++ {
		if !packetSizes[i].isSet {
			continue
		}
		for j := i + 1; j < len(packetSizes); j++ {
			if !packetSizes[j].isSet {
				continue
			}
			if packetSizes[i].size == packetSizes[j].size {
				if config.hasCookieReplyPacketJunkSize || config.hasTransportPacketJunkSize {
					return errors.New(
						"value of the field S1 + message initiation size (148) must not equal S2 + message response size (92) + S3 + cookie reply size (64) + S4 + transport packet size (32)",
					)
				}
				return errors.New(
					"value of the field S1 + message initiation size (148) must not equal S2 + message response size (92)",
				)
			}
		}
	}

	intervals := collectEffectiveHeaderIntervals(config)
	for _, interval := range intervals {
		if interval.min > interval.max {
			return errors.New("invalid magic header range: lower bound cannot exceed upper bound")
		}
	}
	if hasOverlappingHeaderIntervals(intervals) {
		return errors.New("values of the H1-H4 fields must be unique")
	}
	return nil
}

type headerInterval struct {
	key string
	min uint32
	max uint32
}

const (
	defaultInitPacketMagicHeader      uint32 = 1
	defaultResponsePacketMagicHeader  uint32 = 2
	defaultUnderloadPacketMagicHeader uint32 = 3
	defaultTransportPacketMagicHeader uint32 = 4
)

// parseMagicHeaderInterval — без изменений.
func parseMagicHeaderInterval(value string) (uint32, uint32, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, 0, errors.New("empty magic header value")
	}
	parts := strings.Split(trimmed, "-")
	if len(parts) == 0 || len(parts) > 2 || parts[0] == "" {
		return 0, 0, errors.New("invalid magic header range format")
	}
	minRaw, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return 0, 0, err
	}
	minValue := uint32(minRaw)
	if len(parts) == 1 {
		return minValue, minValue, nil
	}
	if parts[1] == "" {
		return 0, 0, errors.New("invalid magic header range format")
	}
	maxRaw, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, 0, err
	}
	maxValue := uint32(maxRaw)
	if minValue > maxValue {
		return 0, 0, errors.New("invalid magic header range: lower bound cannot exceed upper bound")
	}
	return minValue, maxValue, nil
}

// collectEffectiveHeaderIntervals и hasOverlappingHeaderIntervals — без изменений.
func collectEffectiveHeaderIntervals(config *ASecConfigType) []headerInterval {
	intervals := make([]headerInterval, 0, 4)

	h1Min, h1Max := defaultInitPacketMagicHeader, defaultInitPacketMagicHeader
	if config != nil && config.hasInitPacketMagicHeader {
		h1Min, h1Max = config.initPacketMagicHeader, config.initPacketMagicHeaderMax
	}
	intervals = append(intervals, headerInterval{key: "h1", min: h1Min, max: h1Max})

	h2Min, h2Max := defaultResponsePacketMagicHeader, defaultResponsePacketMagicHeader
	if config != nil && config.hasResponsePacketMagicHeader {
		h2Min, h2Max = config.responsePacketMagicHeader, config.responsePacketMagicHeaderMax
	}
	intervals = append(intervals, headerInterval{key: "h2", min: h2Min, max: h2Max})

	h3Min, h3Max := defaultUnderloadPacketMagicHeader, defaultUnderloadPacketMagicHeader
	if config != nil && config.hasUnderloadPacketMagicHeader {
		h3Min, h3Max = config.underloadPacketMagicHeader, config.underloadPacketMagicHeaderMax
	}
	intervals = append(intervals, headerInterval{key: "h3", min: h3Min, max: h3Max})

	h4Min, h4Max := defaultTransportPacketMagicHeader, defaultTransportPacketMagicHeader
	if config != nil && config.hasTransportPacketMagicHeader {
		h4Min, h4Max = config.transportPacketMagicHeader, config.transportPacketMagicHeaderMax
	}
	intervals = append(intervals, headerInterval{key: "h4", min: h4Min, max: h4Max})

	return intervals
}

func hasOverlappingHeaderIntervals(intervals []headerInterval) bool {
	for i := 0; i < len(intervals); i++ {
		for j := i + 1; j < len(intervals); j++ {
			left := intervals[i]
			right := intervals[j]
			if left.min <= right.max && right.min <= left.max {
				return true
			}
		}
	}
	return false
}

// formatMagicHeaderInterval — без изменений.
func formatMagicHeaderInterval(minValue uint32, maxValue uint32) string {
	if minValue == maxValue {
		return strconv.FormatUint(uint64(minValue), 10)
	}
	return strconv.FormatUint(uint64(minValue), 10) + "-" + strconv.FormatUint(uint64(maxValue), 10)
}
