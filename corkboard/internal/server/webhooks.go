package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"corkboard/internal/config"
	"corkboard/internal/model"
)

const (
	webhookTimeout   = 5 * time.Second
	webhookRetries   = 2
	webhookQueueSize = 256
)

func (s *Server) startWebhookAlerts(ctx context.Context) {
	ch, cancel := s.broker.Subscribe()
	go s.consumeWebhookAlerts(ctx, ch, cancel)
}

func (s *Server) consumeWebhookAlerts(ctx context.Context, ch <-chan model.Event, cancel func()) {
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-ch:
			s.dispatchWebhooks(ctx, e)
		}
	}
}

func (s *Server) dispatchWebhooks(ctx context.Context, e model.Event) {
	for _, wh := range s.cfg.Webhooks {
		if !webhookWants(wh.Kinds, e.Kind) {
			continue
		}
		key := fmt.Sprintf("webhook:%s:%s:%d", wh.Name, e.Kind, e.ID)
		seen, err := s.store.AlertSeen(ctx, key)
		if err != nil {
			s.log.Error("webhook dedupe check", "err", err)
			continue
		}
		if seen {
			continue
		}
		if err := s.store.MarkAlertSent(ctx, key); err != nil {
			s.log.Error("webhook dedupe mark", "err", err)
			continue
		}
		go s.deliverWebhook(wh, e)
	}
}

func webhookWants(kinds []string, kind string) bool {
	if len(kinds) == 0 {
		return true
	}
	for _, k := range kinds {
		if k == kind {
			return true
		}
	}
	return false
}

func webhookPayload(format string, e model.Event) ([]byte, string, error) {
	switch format {
	case "", "slack":

		text := fmt.Sprintf("%s: %s", e.Actor, e.Summary)
		data, err := json.Marshal(map[string]string{"text": text})
		return data, "application/json", err
	case "json":
		data, err := json.Marshal(e)
		return data, "application/json", err
	default:
		return nil, "", fmt.Errorf("unknown webhook format %q", format)
	}
}

func (s *Server) deliverWebhook(wh configWebhook, e model.Event) {
	payload, ctype, err := webhookPayload(wh.Format, e)
	if err != nil {
		s.log.Error("webhook payload", "webhook", wh.Name, "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), webhookTimeout)
	defer cancel()
	for attempt := 0; attempt <= webhookRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, strings.NewReader(string(payload)))
		if err != nil {
			s.log.Error("webhook request", "webhook", wh.Name, "err", err)
			return
		}
		req.Header.Set("Content-Type", ctype)
		req.Header.Set("User-Agent", "corkboard")
		resp, err := webhookHTTPClient.Do(req)
		if err == nil && resp.StatusCode < 300 {
			drainAndClose(resp)
			return
		}
		if resp != nil {
			drainAndClose(resp)
		}
		s.log.Warn("webhook attempt failed", "webhook", wh.Name, "attempt", attempt,
			"status", statusCode(resp), "err", err)
	}
}

func statusCode(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}

type configWebhook = config.Webhook

var webhookHTTPClient = &http.Client{}

func drainAndClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
}
