package s3

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	//"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
)

// Helper is our permission-checking helper struct.
// It stores the rclone options plus an http.Client for calls.
type Helper struct {
	opt    Options
	client *http.Client
}

// ErrPermissionDenied signals that the user lacks permission for a folder
var ErrPermissionDenied = errors.New("permission denied by microservice")

// authRequest -> JSON body sent to POST /api/auth/token
type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// authResponse -> JSON returned from /api/auth/token
type authResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// folderInfo -> JSON item returned by GET /api/folders/path
type folderInfo struct {
	FolderId   string `json:"folderId"`
	FolderPath string `json:"folderPath"`
	Role       string `json:"role"` // e.g. "OWNER", "EDITOR", "FULL", "VIEWER", or "NONE"
	// plus other fields if you wish
}

// NewHelperFromConfig constructs the Helper by reading the custom fields
// from rclone’s configmap. Typically called in your backend's NewFs(...).
func NewHelperFromConfig(m configmap.Mapper) (*Helper, error) {
	var opt Options
	if err := configstruct.Set(m, &opt); err != nil {
		return nil, fmt.Errorf("failed to parse rclone config into Options: %w", err)
	}

	// You can log or check that the fields are not empty:
	log.Printf("[NewHelperFromConfig] dc_auth_url=%q dc_folders_url=%q dc_user=%q (pass len=%d)",
		opt.DCAuthURL, opt.DCFoldersURL, opt.DCUser, len(opt.DCPass))

	h := &Helper{
		opt: opt,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	return h, nil
}

// fetchJWT calls POST /api/auth/token using the fields from rclone config
func (h *Helper) fetchJWT(ctx context.Context) (string, error) {
	if h.opt.DCAuthURL == "" {
		return "", errors.New("missing dc_auth_url in rclone config")
	}
	if h.opt.DCUser == "" || h.opt.DCPass == "" {
		return "", errors.New("missing dc_user or dc_pass in rclone config")
	}

	creds := authRequest{
		Username: h.opt.DCUser,
		Password: h.opt.DCPass,
	}
	reqBytes, err := json.Marshal(creds)
	if err != nil {
		return "", fmt.Errorf("failed to encode auth request: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, h.opt.DCAuthURL, bytes.NewBuffer(reqBytes),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth token request returned non-200: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read auth token response: %w", err)
	}

	var ar authResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return "", fmt.Errorf("failed to decode auth token JSON: %w", err)
	}

	if ar.AccessToken == "" {
		return "", errors.New("auth token response contained empty access_token")
	}

	return ar.AccessToken, nil
}

// fetchFolderInfo calls GET /api/folders/path?parentFolderPath=<folderPath>
// and returns the first folder's ID + role
func (h *Helper) fetchFolderInfo(ctx context.Context, bucket, folderPath, token string) (string, string, error) {
	if h.opt.DCFoldersURL == "" {
		return "", "", errors.New("missing dc_folders_url in rclone config")
	}

	// Combine bucket + folderPath if needed, or just pass folderPath alone
	fullPath := folderPath
	// e.g. if you want "bucket/folderPath" => fullPath = bucket + "/" + folderPath
	// depends on your microservice logic

	u, err := url.Parse(h.opt.DCFoldersURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid dc_folders_url: %w", err)
	}
	q := u.Query()
	q.Set("parentFolderPath", fullPath)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create GET request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := h.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("GET call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("GET returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read GET body: %w", err)
	}

	var folders []folderInfo
	if err := json.Unmarshal(body, &folders); err != nil {
		return "", "", fmt.Errorf("failed to decode folder JSON: %w", err)
	}

	if len(folders) == 0 {
		log.Printf("[fetchFolderInfo] no folder found for path=%q => permission denied", fullPath)
		return "", "", ErrPermissionDenied
	}

	// for simplicity, pick the first if there's only one
	folderID := folders[0].FolderId
	role := folders[0].Role
	return folderID, role, nil
}

// CheckPermission is the final method your code calls to see if user can do an action
// action can be "list", "read", "put", "remove", "copy", etc.
// bucket => name of the bucket in rclone's s3 sense
// folderPath => the path under that bucket
func (h *Helper) CheckPermission(ctx context.Context, action, bucket, folderPath string) error {
	token, err := h.fetchJWT(ctx)
	if err != nil {
		return fmt.Errorf("failed to get JWT token: %w", err)
	}

	folderID, role, err := h.fetchFolderInfo(ctx, bucket, folderPath, token)
	if err != nil {
		// If it's an ErrPermissionDenied, pass that up
		if errors.Is(err, ErrPermissionDenied) {
			return err
		}
		return fmt.Errorf("failed to fetch folder info: %w", err)
	}

	log.Printf("[CheckPermission] folderID=%s, role=%q for path=%q => action=%q\n",
		folderID, role, folderPath, action)

	switch strings.ToLower(action) {
	case "list", "read":
		if role == "NONE" {
			return ErrPermissionDenied
		}
	case "put", "remove", "copy":
		if role != "EDITOR" && role != "FULL" && role != "OWNER" {
			return ErrPermissionDenied
		}
	default:
		return ErrPermissionDenied
	}

	return nil
}
