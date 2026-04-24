package logging

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

type DecisionLog struct {
	Time             string `json:"time"`
	ResourceID       string `json:"resource_id"`
	Level            string `json:"level,omitempty"`
	AgentServer      string `json:"agent_server,omitempty"`
	Delegate         string `json:"delegate,omitempty"`
	ResourceTokenJTI string `json:"resource_token_jti,omitempty"`
	Result           string `json:"result"`
	Reason           string `json:"reason,omitempty"`
	LatencyMs        int64  `json:"latency_ms"`
}

var logger = log.New(os.Stdout, "", 0)

func LogDecision(logData DecisionLog) {
	logData.Time = time.Now().UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(logData)
	if err == nil {
		logger.Println(string(b))
	}
}
