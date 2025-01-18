// sg-audittrail/pkg/clientlib/audittraillib/client.go
package audittraillib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

func (c *Client) LogAction(auditTrail AuditTrail) (bool, error) {
	apiUrl := fmt.Sprintf("%s/log-action", c.BaseURL)

	jsonData, err := json.Marshal(auditTrail)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequest(http.MethodPost, apiUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		return false, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-API-Key", c.ApiKey)

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusCreated, nil
}

// Helper function for GET requests
func (c *Client) getAuditTrail(apiUrl string) ([]AuditTrail, error) {
	var auditTrails []AuditTrail

	req, err := http.NewRequest(http.MethodGet, apiUrl, nil)
	if err != nil {
		return auditTrails, err
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-API-Key", c.ApiKey)

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return auditTrails, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return auditTrails, err
	}

	err = json.Unmarshal(body, &auditTrails)
	if err != nil {
		return auditTrails, err
	}

	return auditTrails, nil
}

func (c *Client) GetAuditTrailByEntityID(entityID uuid.UUID) ([]AuditTrail, error) {
	apiUrl := fmt.Sprintf("%s/audit-trail/entity/%s", c.BaseURL, entityID.String())
	return c.getAuditTrail(apiUrl)
}

func (c *Client) GetAuditTrailByUserID(userID uuid.UUID) ([]AuditTrail, error) {
	apiUrl := fmt.Sprintf("%s/audit-trail/user/%s", c.BaseURL, userID.String())
	return c.getAuditTrail(apiUrl)
}

func (c *Client) GetAuditTrailByDateRange(startDate, endDate time.Time) ([]AuditTrail, error) {
	apiUrl := fmt.Sprintf("%s/audit-trail/date-range/%s/%s", c.BaseURL, startDate.Format(time.RFC3339), endDate.Format(time.RFC3339))
	return c.getAuditTrail(apiUrl)
}

func (c *Client) GetAuditTrailByActionType(actionType string) ([]AuditTrail, error) {
	apiUrl := fmt.Sprintf("%s/audit-trail/action-type/%s", c.BaseURL, strings.TrimSpace(actionType))
	return c.getAuditTrail(apiUrl)
}

func (c *Client) GetAuditTrailByEntityName(entityName string) ([]AuditTrail, error) {
	apiUrl := fmt.Sprintf("%s/audit-trail/entity-name/%s", c.BaseURL, strings.TrimSpace(entityName))
	return c.getAuditTrail(apiUrl)
}

func (c *Client) postAuditTrail(apiUrl string, body io.Reader) ([]AuditTrail, error) {
	var auditTrails []AuditTrail

	req, err := http.NewRequest(http.MethodPost, apiUrl, body)
	if err != nil {
		return auditTrails, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-API-Key", c.ApiKey)

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return auditTrails, err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return auditTrails, err
	}

	err = json.Unmarshal(responseBody, &auditTrails)
	if err != nil {
		return auditTrails, err
	}

	return auditTrails, nil
}

func (c *Client) GetFilteredAuditTrail(filter *AuditTrailFilter) ([]AuditTrail, error) {
	apiUrl := fmt.Sprintf("%s/getFilteredAuditTrail", c.BaseURL)

	filterJson, err := json.Marshal(filter)
	if err != nil {
		return nil, err
	}

	return c.postAuditTrail(apiUrl, bytes.NewBuffer(filterJson))
}
