package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
)

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Authorization code not found", http.StatusBadRequest)
		return
	}

	// In mã ủy quyền (authorization code)
	_, err := fmt.Fprintf(w, "Authorization code: %s\n", code)
	if err != nil {
		return
	}
	fmt.Println("Received authorization code:", code)

	// Sau khi nhận được auth code, bạn có thể dùng mã này để lấy access token.
	go func() {
		clientID := os.Getenv("CLIENT_ID")
		clientSecret := os.Getenv("CLIENT_SECRET")
		tenantID := os.Getenv("TENANT_ID")
		redirectURI := os.Getenv("REDIRECT_URI")

		accessToken, err := getAccessToken(clientID, clientSecret, tenantID, redirectURI, code)
		if err != nil {
			fmt.Println("Error getting access token:", err)
			return
		}

		teamID := os.Getenv("TEAM_ID")
		err = getTags(accessToken, teamID)
		if err != nil {
			fmt.Println("Error getting tags:", err)
		}
	}()
}

// Step 1: Redirect user to authorize URL to get authorization code
func getAuthorizeURL(clientID, redirectURI, tenantID string) string {
	authURL := fmt.Sprintf(
		"https://login.microsoftonline.com/%s/oauth2/v2.0/authorize?client_id=%s&response_type=code&redirect_uri=%s&response_mode=query&scope=https://graph.microsoft.com/.default&state=12345",
		tenantID, clientID, url.QueryEscape(redirectURI))

	return authURL
}

// Step 2: Exchange authorization code for access token
func getAccessToken(clientID, clientSecret, tenantID, redirectURI, code string) (string, error) {
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)

	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_secret", clientSecret)
	data.Set("scope", "https://graph.microsoft.com/.default")

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			// handle error
			fmt.Println("Error getting tags:", err)
		}
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	accessToken, ok := result["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("failed to get access token")
	}

	return accessToken, nil
}

// Step 3: Get tags from Microsoft Teams using access token
func getTags(accessToken, teamID string) error {
	tagUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/teams/%s/tags", teamID)

	req, err := http.NewRequest("GET", tagUrl, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println("Error getting tags:", err)
		}
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}

	tags, ok := result["value"].([]interface{})
	if !ok {
		return fmt.Errorf("failed to get tags")
	}

	file, err := os.Create("tags.csv")
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Println("Error getting tags:", err)
		}
	}(file)

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"ID", "DisplayName", "Description"}); err != nil {
		return err
	}

	// Write tags to CSV file
	for _, tag := range tags {
		tagMap, ok := tag.(map[string]interface{})
		if !ok {
			continue
		}

		id, _ := tagMap["id"].(string)
		displayName, _ := tagMap["displayName"].(string)
		description, _ := tagMap["description"].(string)

		if err := writer.Write([]string{id, displayName, description}); err != nil {
			return err
		}
	}

	return nil
}

func main() {
	err := godotenv.Load(".env.local")
	if err != nil {
		log.Fatal("Error loading .env")
	}

	clientID := os.Getenv("CLIENT_ID")
	tenantID := os.Getenv("TENANT_ID")
	redirectURI := os.Getenv("REDIRECT_URI")

	// Step 1: Generate authorize URL và hướng người dùng truy cập
	authorizeURL := getAuthorizeURL(clientID, redirectURI, tenantID)
	fmt.Println("Please visit this URL to authorize the application:")
	fmt.Println(authorizeURL)

	// Step 2: Tạo HTTP server để lắng nghe callback từ Microsoft
	http.HandleFunc("/callback", handleCallback)
	fmt.Printf("Listening on %s for the authorization code...\n", redirectURI)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
