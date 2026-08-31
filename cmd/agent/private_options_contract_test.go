package main

import (
	"encoding/json"
	"testing"

	"golang.zabbix.com/sdk/plugin/comms"
)

func TestSDKPrivateOptionsRepresentation(t *testing.T) {
	t.Parallel()

	var request comms.ValidateRequest
	if err := json.Unmarshal([]byte(`{
		"id":1,
		"type":4,
		"private_options":{
			"Line":1,
			"Name":"DNF",
			"Nodes":[{
				"Line":3,
				"Name":"Backend",
				"Nodes":[{"Line":3,"Value":"YXB0"}]
			}]
		}
	}`), &request); err != nil {
		t.Fatalf("unmarshal SDK validate request: %v", err)
	}

	options, ok := request.PrivateOptions.(map[string]any)
	if !ok {
		t.Fatalf("private options type = %T, want map[string]any", request.PrivateOptions)
	}
	if _, ok := options["Nodes"].([]any); !ok {
		t.Fatalf("private option Nodes = %T, want []any", options["Nodes"])
	}
	if got, err := parseBackendOption(request.PrivateOptions); err != nil || got != backendAPT {
		t.Fatalf("decoded Backend option = (%q, %v), want (apt, nil)", got, err)
	}
}
