package structfields

import (
	"encoding/base64"
	"fmt"
	"math"
	"strings"
)

func SerializeDictionary(dict Dictionary) (string, error) {
	var sb strings.Builder
	for i, member := range dict {
		if i > 0 {
			sb.WriteString(", ")
		}
		if err := serializeKey(&sb, member.Name); err != nil {
			return "", err
		}

		// Boolean true has a special case: name;param1=val1
		if item, ok := member.Value.(Item); ok && isBoolTrue(item.Value) {
			if err := serializeParams(&sb, item.Params); err != nil {
				return "", err
			}
		} else {
			sb.WriteString("=")
			if err := serializeListEntry(&sb, member.Value); err != nil {
				return "", err
			}
		}
	}
	return sb.String(), nil
}

func SerializeList(list List) (string, error) {
	var sb strings.Builder
	for i, entry := range list {
		if i > 0 {
			sb.WriteString(", ")
		}
		if err := serializeListEntry(&sb, entry); err != nil {
			return "", err
		}
	}
	return sb.String(), nil
}

func SerializeItem(item Item) (string, error) {
	var sb strings.Builder
	if err := serializeItem(&sb, item); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func serializeListEntry(sb *strings.Builder, entry ListEntry) error {
	switch v := entry.(type) {
	case Item:
		return serializeItem(sb, v)
	case InnerList:
		sb.WriteString("(")
		for i, item := range v.Items {
			if i > 0 {
				sb.WriteString(" ")
			}
			if err := serializeItem(sb, item); err != nil {
				return err
			}
		}
		sb.WriteString(")")
		return serializeParams(sb, v.Params)
	default:
		return fmt.Errorf("unknown ListEntry type: %T", entry)
	}
}

func serializeItem(sb *strings.Builder, item Item) error {
	if err := serializeBareItem(sb, item.Value); err != nil {
		return err
	}
	return serializeParams(sb, item.Params)
}

func serializeBareItem(sb *strings.Builder, val interface{}) error {
	switch v := val.(type) {
	case int:
		sb.WriteString(fmt.Sprintf("%d", v))
	case int64:
		sb.WriteString(fmt.Sprintf("%d", v))
	case float64:
		// Decimal representation per RFC 8941
		sb.WriteString(formatDecimal(v))
	case string:
		sb.WriteString(`"`)
		for i := 0; i < len(v); i++ {
			c := v[i]
			if c == '"' || c == '\\' {
				sb.WriteByte('\\')
			}
			sb.WriteByte(c)
		}
		sb.WriteString(`"`)
	case Token:
		sb.WriteString(string(v))
	case []byte:
		sb.WriteString(":")
		sb.WriteString(base64.StdEncoding.EncodeToString(v))
		sb.WriteString(":")
	case bool:
		if v {
			sb.WriteString("?1")
		} else {
			sb.WriteString("?0")
		}
	default:
		return fmt.Errorf("unsupported bare item type: %T", val)
	}
	return nil
}

func serializeParams(sb *strings.Builder, params Params) error {
	for _, p := range params {
		sb.WriteString(";")
		if err := serializeKey(sb, p.Name); err != nil {
			return err
		}
		if !isBoolTrue(p.Value) {
			sb.WriteString("=")
			if err := serializeBareItem(sb, p.Value); err != nil {
				return err
			}
		}
	}
	return nil
}

func serializeKey(sb *strings.Builder, key string) error {
	if len(key) == 0 {
		return fmt.Errorf("empty key")
	}
	c := key[0]
	if c != '*' && !(c >= 'a' && c <= 'z') {
		return fmt.Errorf("invalid first char in key: %c", c)
	}
	for i := 1; i < len(key); i++ {
		c := key[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '*') {
			return fmt.Errorf("invalid char in key: %c", c)
		}
	}
	sb.WriteString(key)
	return nil
}

func isBoolTrue(val interface{}) bool {
	b, ok := val.(bool)
	return ok && b
}

func formatDecimal(f float64) string {
	// Simple formatter rounding to up to 3 decimal places
	// To strictly comply with RFC 8941, this needs exact formatting
	// For AAuth, typical decimals are not used heavily, but we'll approximate:
	f = math.Round(f*1000) / 1000
	s := fmt.Sprintf("%g", f)
	if !strings.Contains(s, ".") && !strings.Contains(s, "e") {
		s += ".0"
	}
	return s
}
