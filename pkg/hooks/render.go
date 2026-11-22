package hooks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

type claudeHookOutput struct {
	HookSpecificOutput claudeHookSpecificOutput `json:"hookSpecificOutput"`
}

type claudeHookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

type cursorHookOutput struct {
	Permission   string `json:"permission"`
	UserMessage  string `json:"userMessage"`
	AgentMessage string `json:"agentMessage"`
}

type geminiHookOutput struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// RenderClientResponse writes a single strict, dialect-compliant JSON object to w
// (with zero stray bytes, honoring Gemini CLI's strict stdout silence rule) and
// returns the process exit code.
func RenderClientResponse(w io.Writer, client ClientDialect, event HookEvent, dec *Decision) (int, error) {
	if dec == nil {
		dec = &Decision{Allow: true, Summary: "Allowed."}
	}

	verdict := "deny"
	if dec.Allow {
		verdict = "allow"
	}

	summary := sanitizeOutputText(dec.Summary)
	remediation := sanitizeOutputText(dec.RemediationCmd)
	why := sanitizeOutputText(dec.Why)

	if summary == "" {
		if dec.Allow {
			summary = "Allowed by Fabrial security hook."
		} else {
			summary = "Blocked by Fabrial security hook."
		}
	}

	reason := summary
	if !dec.Allow && remediation != "" {
		reason = fmt.Sprintf("%s Fix: %s", summary, remediation)
	}
	if !dec.Allow && dec.ReceiptID != "" {
		reason = fmt.Sprintf("%s [receipt=%s]", reason, sanitizeSingleLineText(dec.ReceiptID))
	}

	var payload interface{}
	switch client {
	case ClientClaude:
		evName := "PreToolUse"
		if event == EventPostTool {
			evName = "PostToolUse"
		}
		payload = claudeHookOutput{
			HookSpecificOutput: claudeHookSpecificOutput{
				HookEventName:            evName,
				PermissionDecision:       verdict,
				PermissionDecisionReason: reason,
			},
		}

	case ClientCursor:
		agentMsg := reason
		if !dec.Allow && why != "" {
			agentMsg = fmt.Sprintf("%s (%s)", reason, why)
		}
		payload = cursorHookOutput{
			Permission:   verdict,
			UserMessage:  summary,
			AgentMessage: agentMsg,
		}

	case ClientGemini:
		payload = geminiHookOutput{
			Decision: verdict,
			Reason:   reason,
		}

	default:
		return 1, fmt.Errorf("unsupported hook client dialect %q", client)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return 1, fmt.Errorf("marshal %s hook response: %w", client, err)
	}

	if _, err := w.Write(buf.Bytes()); err != nil {
		return 1, fmt.Errorf("write %s hook response: %w", client, err)
	}

	if !dec.Allow && dec.HardBlock {
		return 2, nil
	}
	return 0, nil
}
