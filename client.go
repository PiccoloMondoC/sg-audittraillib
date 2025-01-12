// sg-audittrail/pkg/clientlib/audittraillib/client.go
package audittraillib

import (
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Client represents an HTTP client that can be used to send requests to the audit trail server.
type Client struct {
	BaseURL    string
	HttpClient *http.Client
	Token      string
	ApiKey     string
}

type AuditTrail struct {
	ID         uuid.UUID `json:"id"`
	UserID     uuid.UUID `json:"user_id"`
	ActionType string    `json:"action_type"`
	EntityName string    `json:"entity_name"`
	EntityID   uuid.UUID `json:"entity_id"`
	ChangeData string    `json:"change_data"` // or use a custom type if needed
	Timestamp  time.Time `json:"timestamp"`
}

type AuditTrailFilter struct {
	UserID     *uuid.UUID
	ActionType *string
	EntityName *string
	StartDate  *time.Time
	EndDate    *time.Time
}

func NewClient(baseURL string, token string, apiKey string, httpClient ...*http.Client) *Client {
	var client *http.Client
	if len(httpClient) > 0 {
		client = httpClient[0]
	} else {
		client = &http.Client{
			Timeout: time.Second * 10,
		}
	}

	return &Client{
		BaseURL:    baseURL,
		HttpClient: client,
		Token:      token,
		ApiKey:     apiKey,
	}
}
