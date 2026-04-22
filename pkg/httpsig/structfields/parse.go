package structfields

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidFormat = errors.New("invalid structured field format")
)

type scanner struct {
	s   string
	pos int
}

func (sc *scanner) skipSP() {
	for sc.pos < len(sc.s) && sc.s[sc.pos] == ' ' {
		sc.pos++
	}
}

func (sc *scanner) skipOWS() {
	for sc.pos < len(sc.s) && (sc.s[sc.pos] == ' ' || sc.s[sc.pos] == '\t') {
		sc.pos++
	}
}

func (sc *scanner) eof() bool {
	return sc.pos >= len(sc.s)
}

func (sc *scanner) peek() byte {
	if sc.pos >= len(sc.s) {
		return 0
	}
	return sc.s[sc.pos]
}

func (sc *scanner) next() byte {
	if sc.pos >= len(sc.s) {
		return 0
	}
	b := sc.s[sc.pos]
	sc.pos++
	return b
}

func ParseDictionary(input string) (Dictionary, error) {
	sc := &scanner{s: input}
	sc.skipSP()
	dict, err := sc.parseDictionary()
	if err != nil {
		return nil, err
	}
	sc.skipSP()
	if !sc.eof() {
		return nil, fmt.Errorf("%w: trailing characters", ErrInvalidFormat)
	}
	return dict, nil
}

func ParseList(input string) (List, error) {
	sc := &scanner{s: input}
	sc.skipSP()
	list, err := sc.parseList()
	if err != nil {
		return nil, err
	}
	sc.skipSP()
	if !sc.eof() {
		return nil, fmt.Errorf("%w: trailing characters", ErrInvalidFormat)
	}
	return list, nil
}

func ParseItem(input string) (Item, error) {
	sc := &scanner{s: input}
	sc.skipSP()
	item, err := sc.parseItem()
	if err != nil {
		return Item{}, err
	}
	sc.skipSP()
	if !sc.eof() {
		return Item{}, fmt.Errorf("%w: trailing characters", ErrInvalidFormat)
	}
	return item, nil
}

func (sc *scanner) parseDictionary() (Dictionary, error) {
	var dict Dictionary
	for !sc.eof() {
		name, err := sc.parseKey()
		if err != nil {
			return nil, err
		}
		var value ListEntry
		if sc.peek() == '=' {
			sc.next() // consume '='
			value, err = sc.parseListEntry()
			if err != nil {
				return nil, err
			}
		} else {
			// Boolean true with params
			params, err := sc.parseParams()
			if err != nil {
				return nil, err
			}
			value = Item{Value: true, Params: params}
		}

		// If name already exists, overwrite it (RFC 8941 section 4.2: "If a name already appears... overwrite")
		idx := -1
		for i, m := range dict {
			if m.Name == name {
				idx = i
				break
			}
		}
		if idx >= 0 {
			dict[idx].Value = value
		} else {
			dict = append(dict, DictMember{Name: name, Value: value})
		}

		sc.skipOWS()
		if sc.eof() {
			break
		}
		if sc.next() != ',' {
			return nil, fmt.Errorf("%w: expected ',' in dictionary", ErrInvalidFormat)
		}
		sc.skipOWS()
		if sc.eof() {
			return nil, fmt.Errorf("%w: trailing comma in dictionary", ErrInvalidFormat)
		}
	}
	return dict, nil
}

func (sc *scanner) parseList() (List, error) {
	var list List
	for !sc.eof() {
		entry, err := sc.parseListEntry()
		if err != nil {
			return nil, err
		}
		list = append(list, entry)
		sc.skipOWS()
		if sc.eof() {
			break
		}
		if sc.next() != ',' {
			return nil, fmt.Errorf("%w: expected ',' in list", ErrInvalidFormat)
		}
		sc.skipOWS()
		if sc.eof() {
			return nil, fmt.Errorf("%w: trailing comma in list", ErrInvalidFormat)
		}
	}
	return list, nil
}

func (sc *scanner) parseListEntry() (ListEntry, error) {
	if sc.peek() == '(' {
		return sc.parseInnerList()
	}
	return sc.parseItem()
}

func (sc *scanner) parseInnerList() (InnerList, error) {
	var list InnerList
	if sc.next() != '(' {
		return list, fmt.Errorf("%w: expected '('", ErrInvalidFormat)
	}
	for !sc.eof() {
		sc.skipSP()
		if sc.peek() == ')' {
			sc.next()
			params, err := sc.parseParams()
			if err != nil {
				return list, err
			}
			list.Params = params
			return list, nil
		}
		item, err := sc.parseItem()
		if err != nil {
			return list, err
		}
		list.Items = append(list.Items, item)
		if sc.peek() != ' ' && sc.peek() != ')' {
			return list, fmt.Errorf("%w: expected space or ')' in inner list", ErrInvalidFormat)
		}
	}
	return list, fmt.Errorf("%w: unclosed inner list", ErrInvalidFormat)
}

func (sc *scanner) parseItem() (Item, error) {
	val, err := sc.parseBareItem()
	if err != nil {
		return Item{}, err
	}
	params, err := sc.parseParams()
	if err != nil {
		return Item{}, err
	}
	return Item{Value: val, Params: params}, nil
}

func (sc *scanner) parseBareItem() (interface{}, error) {
	p := sc.peek()
	if p == '-' || (p >= '0' && p <= '9') {
		return sc.parseNumber()
	}
	if p == '"' {
		return sc.parseString()
	}
	if p == '*' || (p >= 'a' && p <= 'z') || (p >= 'A' && p <= 'Z') {
		return sc.parseToken()
	}
	if p == ':' {
		return sc.parseByteSequence()
	}
	if p == '?' {
		return sc.parseBoolean()
	}
	return nil, fmt.Errorf("%w: invalid start of item: %c", ErrInvalidFormat, p)
}

func (sc *scanner) parseKey() (string, error) {
	p := sc.peek()
	if p != '*' && !(p >= 'a' && p <= 'z') {
		return "", fmt.Errorf("%w: invalid start of key", ErrInvalidFormat)
	}
	start := sc.pos
	for !sc.eof() {
		p = sc.peek()
		if (p >= 'a' && p <= 'z') || (p >= '0' && p <= '9') || p == '_' || p == '-' || p == '.' || p == '*' {
			sc.pos++
		} else {
			break
		}
	}
	return sc.s[start:sc.pos], nil
}

func (sc *scanner) parseParams() (Params, error) {
	var params Params
	for sc.peek() == ';' {
		sc.next() // consume ';'
		sc.skipSP()
		name, err := sc.parseKey()
		if err != nil {
			return nil, err
		}
		var value interface{} = true
		if sc.peek() == '=' {
			sc.next()
			value, err = sc.parseBareItem()
			if err != nil {
				return nil, err
			}
		}
		// Overwrite param if it exists
		idx := -1
		for i, p := range params {
			if p.Name == name {
				idx = i
				break
			}
		}
		if idx >= 0 {
			params[idx].Value = value
		} else {
			params = append(params, Param{Name: name, Value: value})
		}
	}
	return params, nil
}

func (sc *scanner) parseBoolean() (bool, error) {
	if sc.next() != '?' {
		return false, fmt.Errorf("%w: expected '?'", ErrInvalidFormat)
	}
	p := sc.next()
	if p == '1' {
		return true, nil
	}
	if p == '0' {
		return false, nil
	}
	return false, fmt.Errorf("%w: invalid boolean value", ErrInvalidFormat)
}

func (sc *scanner) parseToken() (Token, error) {
	start := sc.pos
	for !sc.eof() {
		p := sc.peek()
		if p == '!' || p == '#' || p == '$' || p == '%' || p == '&' || p == '\'' || p == '*' || p == '+' || p == '-' || p == '.' || p == '^' || p == '_' || p == '`' || p == '|' || p == '~' || (p >= '0' && p <= '9') || (p >= 'a' && p <= 'z') || (p >= 'A' && p <= 'Z') || p == ':' || p == '/' {
			sc.pos++
		} else {
			break
		}
	}
	return Token(sc.s[start:sc.pos]), nil
}

func (sc *scanner) parseString() (string, error) {
	if sc.next() != '"' {
		return "", fmt.Errorf("%w: expected '\"'", ErrInvalidFormat)
	}
	var sb strings.Builder
	for !sc.eof() {
		c := sc.next()
		if c == '\\' {
			if sc.eof() {
				return "", fmt.Errorf("%w: unclosed string", ErrInvalidFormat)
			}
			nc := sc.next()
			if nc != '"' && nc != '\\' {
				return "", fmt.Errorf("%w: invalid escape sequence", ErrInvalidFormat)
			}
			sb.WriteByte(nc)
		} else if c == '"' {
			return sb.String(), nil
		} else if c >= 0x20 && c <= 0x7E {
			sb.WriteByte(c)
		} else {
			return "", fmt.Errorf("%w: invalid character in string", ErrInvalidFormat)
		}
	}
	return "", fmt.Errorf("%w: unclosed string", ErrInvalidFormat)
}

func (sc *scanner) parseByteSequence() ([]byte, error) {
	if sc.next() != ':' {
		return nil, fmt.Errorf("%w: expected ':'", ErrInvalidFormat)
	}
	start := sc.pos
	for !sc.eof() && sc.peek() != ':' {
		sc.pos++
	}
	if sc.eof() {
		return nil, fmt.Errorf("%w: unclosed byte sequence", ErrInvalidFormat)
	}
	b64 := sc.s[start:sc.pos]
	sc.next() // consume closing ':'

	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// Fallback to base64url without padding (common client error)
		decoded, err = base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			// Fallback to base64url with padding
			decoded, err = base64.URLEncoding.DecodeString(b64)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid base64: %v", ErrInvalidFormat, err)
			}
		}
	}
	return decoded, nil
}

func (sc *scanner) parseNumber() (interface{}, error) {
	sign := 1
	if sc.peek() == '-' {
		sign = -1
		sc.pos++
	}
	if sc.eof() || sc.peek() < '0' || sc.peek() > '9' {
		return nil, fmt.Errorf("%w: expected digit", ErrInvalidFormat)
	}

	var intPart int64
	var lenInt int

	for !sc.eof() && sc.peek() >= '0' && sc.peek() <= '9' {
		intPart = intPart*10 + int64(sc.peek()-'0')
		sc.pos++
		lenInt++
		if lenInt > 15 {
			return nil, fmt.Errorf("%w: integer part too long", ErrInvalidFormat)
		}
	}

	if sc.peek() == '.' {
		sc.pos++
		if lenInt > 12 {
			return nil, fmt.Errorf("%w: decimal integer part too long", ErrInvalidFormat)
		}

		var decPart float64
		var decDiv float64 = 1.0
		var lenDec int

		for !sc.eof() && sc.peek() >= '0' && sc.peek() <= '9' {
			decPart = decPart*10 + float64(sc.peek()-'0')
			decDiv *= 10
			sc.pos++
			lenDec++
			if lenDec > 3 {
				return nil, fmt.Errorf("%w: fractional part too long", ErrInvalidFormat)
			}
		}
		if lenDec == 0 {
			return nil, fmt.Errorf("%w: expected digit after decimal point", ErrInvalidFormat)
		}

		val := float64(intPart) + (decPart / decDiv)
		if sign < 0 {
			val = -val
		}
		return val, nil
	}

	val := intPart
	if sign < 0 {
		val = -val
	}
	return val, nil
}
