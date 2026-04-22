package logging

import (
	"encoding/json"
	"sort"
	"strings"
)

type HeaderSnapshot struct {
	HeaderNames     []string            `json:"header_names"`
	RelevantHeaders map[string][]string `json:"relevant_headers"`
}

func FormatRelevantHeaders(headers map[string][]string) string {
	names := make([]string, 0, len(headers))
	relevant := make(map[string][]string)

	for k, v := range headers {
		key := strings.ToLower(k)
		names = append(names, key)
		if isRelevantHeader(key) {
			relevant[key] = append([]string(nil), v...)
		}
	}

	sort.Strings(names)

	relevantNames := make([]string, 0, len(relevant))
	for k := range relevant {
		relevantNames = append(relevantNames, k)
	}
	sort.Strings(relevantNames)

	orderedRelevant := make(map[string][]string, len(relevantNames))
	for _, k := range relevantNames {
		orderedRelevant[k] = relevant[k]
	}

	b, err := json.Marshal(HeaderSnapshot{
		HeaderNames:     names,
		RelevantHeaders: orderedRelevant,
	})
	if err != nil {
		return `{"header_names":[],"relevant_headers":{}}`
	}
	return string(b)
}

func isRelevantHeader(key string) bool {
	if strings.HasPrefix(key, "aauth-") {
		return true
	}
	if strings.Contains(key, "signature") {
		return true
	}
	if strings.Contains(key, "authorization") {
		return true
	}
	if strings.Contains(key, "digest") {
		return true
	}

	switch key {
	case "host", "content-type", "content-length", "date":
		return true
	default:
		return false
	}
}
