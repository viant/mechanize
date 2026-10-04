package consent

import (
	"context"
	"fmt"
)

type RequestStatus struct {
	Request Request `json:"request"`
	Grant   *Grant  `json:"grant,omitempty"`
	Status  string  `json:"status"`
}

func (s *Service) RequestStatus(ctx context.Context, id string) (RequestStatus, error) {
	c, err := s.client(ctx)
	if err != nil {
		return RequestStatus{}, err
	}
	rows, err := s.read(ctx, "consentrequests", id, c.ID)
	if err != nil {
		return RequestStatus{}, err
	}
	for _, r := range rows {
		if r.ID != id || r.ClientID != c.ID || r.SessionID != c.SessionID {
			continue
		}
		request, err := r.request()
		if err != nil {
			return RequestStatus{}, err
		}
		out := RequestStatus{Request: request, Status: r.Decision}
		if out.Status == "" {
			out.Status = "pending"
			if r.RequestExpiresAt <= int(s.options.Now().UnixMilli()) {
				out.Status = "expired"
			}
		}
		if (r.Decision == string(AllowOnce) || r.Decision == string(AllowSession) || r.permanent()) && r.GrantState != "" && r.GrantState != "none" {
			g, err := r.grant(s.options.Now())
			if err != nil {
				return RequestStatus{}, err
			}
			out.Grant = &g
		}
		return out, nil
	}
	return RequestStatus{}, fmt.Errorf("owned request is unavailable")
}
