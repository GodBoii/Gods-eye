// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"encoding/base64"
	"fmt"
)

// ToolRequest is a bounded assessment request. Engine execution is opt-in.
// Input carries text or base64 bytes, never an executable command or file path.
type ToolRequest struct {
	Tool       string `json:"tool"`
	Target     string `json:"target"`
	Input      string `json:"input"`
	Encoding   string `json:"encoding"`
	Ports      []int  `json:"ports"`
	Authorized bool   `json:"authorized"`
	RunEngine  bool   `json:"runEngine"`
}

func toolInput(request ToolRequest) ([]byte, error) {
	if len(request.Input) > MaxInput {
		return nil, fmt.Errorf("tool input exceeds the 8 MiB limit")
	}
	switch request.Encoding {
	case "", "text":
		return []byte(request.Input), nil
	case "base64":
		data, err := base64.StdEncoding.DecodeString(request.Input)
		if err != nil {
			return nil, fmt.Errorf("input is not valid base64")
		}
		return data, nil
	default:
		return nil, fmt.Errorf("choose text or base64 input encoding")
	}
}
