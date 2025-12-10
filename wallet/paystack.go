package wallet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hng-stage8/definitions"
	"net/http"
	"time"
)

func callPaystackInitialize(amount int64, email string) (*definitions.PaystackInitResponse, error) {
	reqBody, _ := json.Marshal(map[string]any{
		"amount": amount,
		"email":  email,
	})

	req, _ := http.NewRequest("POST", definitions.PaystackBaseURL+"/transaction/initialize", bytes.NewBuffer(reqBody))
	req.Header.Set("Authorization", "Bearer "+definitions.PaystackSecretKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return nil, fmt.Errorf("paystack returned status: %d", resp.StatusCode)
	}

	var wrapper struct {
		Status  bool                             `json:"status"`
		Message string                           `json:"message"`
		Data    definitions.PaystackInitResponse `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, err
	}

	return &wrapper.Data, nil
}
