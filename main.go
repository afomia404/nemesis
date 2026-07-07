package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("failed")
		return
	}
	targetURL := os.Args[1]
	vulnType := os.Args[2]
	payload := os.Args[3]

	client := &http.Client{}
	var req *http.Request
	var err error

	switch vulnType {
	case "SQL Injection":
		u, err := url.Parse(targetURL)
		if err != nil {
			fmt.Println("failed")
			return
		}
		q := u.Query()
		q.Set("username", payload)
		q.Set("password", "anything")
		u.RawQuery = q.Encode()
		req, err = http.NewRequest("GET", u.String(), nil)
		if err != nil {
			fmt.Println("failed")
			return
		}
	// add other cases if needed, but for testing only SQL Injection is enough
	default:
		fmt.Println("failed")
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("failed")
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("failed")
		return
	}

	var bodyMap map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &bodyMap); err != nil {
		fmt.Println("failed")
		return
	}

	if bypass, ok := bodyMap["bypass"].(bool); ok && bypass {
		fmt.Println("success")
	} else {
		fmt.Println("failed")
	}
}