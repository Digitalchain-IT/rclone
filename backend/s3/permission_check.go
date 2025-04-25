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

	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
)

// -----------------------------------------------------------------------------
// Helper struct referencing the pre-defined Options (above).
// -----------------------------------------------------------------------------

type Helper struct {
	opt    Options
	client *http.Client
}

// Sentinel error used to signal "no permission" from the microservice
var ErrPermissionDenied = errors.New("permission denied by microservice")

// authRequest -> JSON for POST /auth/token
type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// authResponse -> JSON response from /auth/token
type authResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// folderInfo -> JSON record for folders from listing endpoints
type folderInfo struct {
	FolderId   string `json:"folderId"`
	FolderName string `json:"folderName"`
	FolderPath string `json:"folderPath"`
	Role       string `json:"role"` // e.g. "OWNER", "FULL", "EDITOR", "VIEWER", "NONE"
}

// privateFolderError -> If GET /api/folders/private returns an error object
type privateFolderError struct {
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
	Timestamp    int64  `json:"timestamp"`
	Details      string `json:"details"`
}

// -----------------------------------------------------------------------------
// NewHelperFromConfig: constructor loading from rclone config
// -----------------------------------------------------------------------------

func NewHelperFromConfig(m configmap.Mapper) (*Helper, error) {
	var opt Options
	if err := configstruct.Set(m, &opt); err != nil {
		return nil, fmt.Errorf("failed to parse rclone config into Options: %w", err)
	}

	log.Printf(
		"[NewHelperFromConfig] dc_auth_url=%q dc_folders_url=%q dc_folder_create_url=%q dc_folder_delete_url=%q dc_user=%q (pass len=%d)",
		opt.DCAuthURL,
		opt.DCFoldersURL,
		opt.DCFolderCreateURL,
		opt.DCFolderDeleteURL,
		opt.DCUser,
		len(opt.DCPass),
	)

	h := &Helper{
		opt: opt,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	return h, nil
}

// -----------------------------------------------------------------------------
// fetchJWT => do POST to h.opt.DCAuthURL
// -----------------------------------------------------------------------------

func (h *Helper) fetchJWT(ctx context.Context) (string, error) {
	if h.opt.DCAuthURL == "" {
		return "", errors.New("missing dc_auth_url in config")
	}
	if h.opt.DCUser == "" || h.opt.DCPass == "" {
		return "", errors.New("missing dc_user or dc_pass in config")
	}

	body, _ := json.Marshal(authRequest{Username: h.opt.DCUser, Password: h.opt.DCPass})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.opt.DCAuthURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth token => status %d", resp.StatusCode)
	}
	data, _ := io.ReadAll(resp.Body)

	var ar authResponse
	if e := json.Unmarshal(data, &ar); e != nil {
		return "", fmt.Errorf("decoding auth token: %w", e)
	}
	if ar.AccessToken == "" {
		return "", errors.New("empty token in response")
	}
	log.Printf("[fetchJWT] success, token len=%d", len(ar.AccessToken))
	return ar.AccessToken, nil
}

// -----------------------------------------------------------------------------
// fetchFolderIDAndRole => path-walk using public + private
// -----------------------------------------------------------------------------

func (h *Helper) fetchFolderIDAndRole(ctx context.Context, folderPath string, token string) (string, string, error) {
	if folderPath == "" {
		log.Println("[fetchFolderIDAndRole] empty path => returning empty ID/role")
		return "", "", nil
	}

	parts := strings.Split(strings.Trim(folderPath, "/"), "/")
	var parentPath string
	var currentFolderID, currentRole string

	for _, segment := range parts {
		allFolders, err := h.listFoldersCombined(ctx, parentPath, token)
		if err != nil {
			return "", "", fmt.Errorf("listFoldersCombined for parent=%q: %w", parentPath, err)
		}

		found := false
		for _, f := range allFolders {
			trim := strings.TrimSuffix(f.FolderPath, "/")
			base := trim
			if idx := strings.LastIndex(trim, "/"); idx >= 0 {
				base = trim[idx+1:]
			}
			if base == segment {
				currentFolderID = f.FolderId
				currentRole = f.Role
				parentPath = f.FolderPath
				found = true
				break
			}
		}
		if !found {
			return "", "", ErrPermissionDenied
		}
	}

	return currentFolderID, currentRole, nil
}

// -----------------------------------------------------------------------------
// listFoldersCombined => merges public + private folder
// -----------------------------------------------------------------------------

func (h *Helper) listFoldersCombined(ctx context.Context, parent string, token string) ([]folderInfo, error) {
	public, err := h.listPublicSubfolders(ctx, parent, token)
	if err != nil {
		return nil, err
	}

	privateFolder, err := h.getPrivateFolderOr404(ctx, token)
	// If error is a real error => bubble up; else if "no private" => ignore
	if err != nil {
		var e *url.Error
		if errors.As(err, &e) {
			return nil, err
		}
		privateFolder = nil
	}

	var privateSlice []folderInfo
	if privateFolder != nil {
		if parent == "" {
			// top-level check
			if !strings.Contains(strings.TrimSuffix(privateFolder.FolderPath, "/"), "/") {
				privateSlice = append(privateSlice, *privateFolder)
			}
		} else {
			p := parent
			if !strings.HasSuffix(p, "/") {
				p += "/"
			}
			pathTrim := strings.TrimSuffix(privateFolder.FolderPath, "/")
			idx := strings.LastIndex(pathTrim, "/")
			var actualParent string
			if idx == -1 {
				actualParent = ""
			} else {
				actualParent = pathTrim[:idx+1]
			}
			if actualParent == p {
				privateSlice = append(privateSlice, *privateFolder)
			}
		}
	}

	return append(public, privateSlice...), nil
}

// -----------------------------------------------------------------------------
// listPublicSubfolders => GET h.opt.DCFoldersURL?parentFolderPath=...
// -----------------------------------------------------------------------------

func (h *Helper) listPublicSubfolders(ctx context.Context, parent string, token string) ([]folderInfo, error) {
	if h.opt.DCFoldersURL == "" {
		return nil, errors.New("dc_folders_url not set")
	}

	u, err := url.Parse(h.opt.DCFoldersURL)
	if err != nil {
		return nil, fmt.Errorf("invalid dc_folders_url: %w", err)
	}

	if parent != "" {
		if !strings.HasSuffix(parent, "/") {
			parent += "/"
		}
		q := u.Query()
		q.Set("parentFolderPath", parent)
		u.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GET: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("listPublicSubfolders GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("listPublicSubfolders => status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)

	var folders []folderInfo
	if e := json.Unmarshal(body, &folders); e != nil {
		return nil, fmt.Errorf("decode public subfolders: %w", e)
	}
	return folders, nil
}

// -----------------------------------------------------------------------------
// getPrivateFolderOr404 => GET h.opt.DCPrivateFolderURL
// -----------------------------------------------------------------------------

func (h *Helper) getPrivateFolderOr404(ctx context.Context, token string) (*folderInfo, error) {
	if h.opt.DCPrivateFolderURL == "" {
		// no private folder endpoint => ignore
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.opt.DCPrivateFolderURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create GET private: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("private GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errObj privateFolderError
		raw, _ := io.ReadAll(resp.Body)
		if e := json.Unmarshal(raw, &errObj); e == nil && errObj.ErrorCode != "" {
			return nil, fmt.Errorf("private folder error => %s: %s", errObj.ErrorCode, errObj.ErrorMessage)
		}
		return nil, fmt.Errorf("private => status %d", resp.StatusCode)
	}

	raw, _ := io.ReadAll(resp.Body)
	var folder folderInfo
	if e := json.Unmarshal(raw, &folder); e != nil {
		var errObj privateFolderError
		if e2 := json.Unmarshal(raw, &errObj); e2 == nil && errObj.ErrorCode != "" {
			return nil, fmt.Errorf("private folder error => %s: %s", errObj.ErrorCode, errObj.ErrorMessage)
		}
		return nil, fmt.Errorf("decode private folder JSON: %w", e)
	}
	return &folder, nil
}

// -----------------------------------------------------------------------------
// createFolderRecord => POST h.opt.DCFolderCreateURL
// -----------------------------------------------------------------------------

func (h *Helper) createFolderRecord(ctx context.Context, token, parentID, folderName string, isProject bool) (string, error) {
	if h.opt.DCFolderCreateURL == "" {
		return "", errors.New("dc_folder_create_url not set in config")
	}
	if parentID == "" {
		return "", errors.New("parentID cannot be empty for create")
	}
	if folderName == "" {
		return "", errors.New("folderName cannot be empty")
	}

	bodyMap := map[string]interface{}{
		"folderName":     folderName,
		"parentFolderId": parentID,
		"project":        isProject,
	}
	data, _ := json.Marshal(bodyMap)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.opt.DCFolderCreateURL, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("failed to create POST for folder create: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("folder create call failed: %w", err)
	}
	defer resp.Body.Close()

	// some microservices respond 200 or 201 on creation
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("create folder => status %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var created struct {
		FolderId string `json:"folderId"`
	}
	if e := json.Unmarshal(body, &created); e != nil {
		return "", fmt.Errorf("decode createFolder response: %w", e)
	}
	if created.FolderId == "" {
		return "", errors.New("create folder => empty folderId in response")
	}
	log.Printf("[createFolderRecord] new folderID=%q", created.FolderId)
	return created.FolderId, nil
}

// -----------------------------------------------------------------------------
// deleteFolderRecord => DELETE h.opt.DCFolderDeleteURL + "/<folderID>"
// -----------------------------------------------------------------------------

func (h *Helper) deleteFolderRecord(ctx context.Context, token, folderID string) error {
	if h.opt.DCFolderDeleteURL == "" {
		return errors.New("dc_folder_delete_url not set")
	}
	if folderID == "" {
		return errors.New("folderID is empty")
	}

	base := h.opt.DCFolderDeleteURL
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	delURL := base + folderID

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, delURL, nil)
	if err != nil {
		return fmt.Errorf("create DELETE request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("delete folder call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("delete folder => status %d", resp.StatusCode)
	}

	log.Printf("[deleteFolderRecord] success => folderID=%s removed", folderID)
	return nil
}

// -----------------------------------------------------------------------------
// Splitting the path: just a small helper
// -----------------------------------------------------------------------------

func splitOffLastSegment(folderPath string) (string, string) {
	path := strings.TrimSuffix(folderPath, "/")
	if path == "" {
		return "", ""
	}
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return "", path
	}
	parent := path[:idx]
	final := path[idx+1:]
	return parent, final
}

// -----------------------------------------------------------------------------
// RemoveFolder => calls the actual delete (example usage).
// -----------------------------------------------------------------------------

func (h *Helper) RemoveFolder(ctx context.Context, folderPath string) error {
	if folderPath == "" {
		return errors.New("folderPath is empty")
	}

	token, err := h.fetchJWT(ctx)
	if err != nil {
		return err
	}

	// find the folder ID
	folderID, role, e := h.fetchFolderIDAndRole(ctx, folderPath, token)
	if e != nil {
		if errors.Is(e, ErrPermissionDenied) {
			return e
		}
		return fmt.Errorf("lookup folderID: %w", e)
	}
	if folderID == "" {
		return ErrPermissionDenied
	}

	// must be editor/full/owner to remove
	if role != "EDITOR" && role != "FULL" && role != "OWNER" {
		return ErrPermissionDenied
	}

	// do the deletion
	return h.deleteFolderRecord(ctx, token, folderID)
}

// -----------------------------------------------------------------------------
// renameFolderRecord => PATCH /api/folders/{folderId}/rename?newName=...
// -----------------------------------------------------------------------------

func (h *Helper) renameFolderRecord(ctx context.Context, token, folderID, newName string) (string, error) {
	if folderID == "" {
		return "", errors.New("renameFolderRecord: folderID cannot be empty")
	}
	if newName == "" {
		return "", errors.New("renameFolderRecord: newName cannot be empty")
	}

	base := h.opt.DCFolderRenameURL
	if base == "" {
		return "", errors.New("missing rename folder URL in config: DCFolderRenameURL")
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}

	// e.g. http://localhost:8222/api/folders/{folderID}/rename?newName=...
	renameURL := fmt.Sprintf("%s%s/rename?newName=%s", base, folderID, url.QueryEscape(newName))

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, renameURL, nil)
	if err != nil {
		return "", fmt.Errorf("rename folder: create PATCH request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := h.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("rename folder call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("rename folder => status %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var renamed struct {
		FolderId   string `json:"folderId"`
		FolderName string `json:"folderName"`
		FolderPath string `json:"folderPath"`
	}
	if err := json.Unmarshal(body, &renamed); err != nil {
		return "", fmt.Errorf("decode renameFolder response: %w", err)
	}
	if renamed.FolderId == "" {
		return "", errors.New("rename folder => empty folderId in response")
	}

	log.Printf("[renameFolderRecord] success => new folderID=%q name=%q path=%q",
		renamed.FolderId, renamed.FolderName, renamed.FolderPath,
	)
	return renamed.FolderId, nil
}

// RenameFolder => rename an existing folder to a new name
func (h *Helper) RenameFolder(ctx context.Context, oldFolderPath, newName string) error {
	if oldFolderPath == "" {
		return errors.New("RenameFolder: old folder path is empty")
	}
	if newName == "" {
		return errors.New("RenameFolder: newName is empty")
	}

	token, err := h.fetchJWT(ctx)
	if err != nil {
		return err
	}

	// 1) Look up folder ID & role
	folderID, role, err := h.fetchFolderIDAndRole(ctx, oldFolderPath, token)
	if err != nil {
		if errors.Is(err, ErrPermissionDenied) {
			return err
		}
		return fmt.Errorf("RenameFolder: fetchFolderIDAndRole => %w", err)
	}
	if folderID == "" {
		return ErrPermissionDenied
	}

	// 2) Check if user’s role is sufficient to rename
	if role != "EDITOR" && role != "FULL" && role != "OWNER" {
		return ErrPermissionDenied
	}

	// 3) Do the actual rename call
	_, err = h.renameFolderRecord(ctx, token, folderID, newName)
	if err != nil {
		return fmt.Errorf("RenameFolder => renameFolderRecord => %w", err)
	}

	log.Printf("[RenameFolder] => oldPath=%q => newName=%q => success", oldFolderPath, newName)
	return nil
}

// -----------------------------------------------------------------------------
// moveFolderRecord => PATCH /api/folders/{folderId}/move?destinationFolderId=...
// -----------------------------------------------------------------------------

func (h *Helper) moveFolderRecord(ctx context.Context, token, folderID, destinationFolderID string) error {
	if folderID == "" {
		return errors.New("moveFolderRecord: source folderID cannot be empty")
	}
	if destinationFolderID == "" {
		return errors.New("moveFolderRecord: destination folderID cannot be empty")
	}

	base := h.opt.DCFolderMoveURL
	if base == "" {
		return errors.New("missing DCFolderMoveURL in config")
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}

	moveURL := fmt.Sprintf("%s%s/move?destinationFolderId=%s",
		base,
		folderID,
		url.QueryEscape(destinationFolderID),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, moveURL, nil)
	if err != nil {
		return fmt.Errorf("moveFolderRecord: create PATCH request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("moveFolderRecord: call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("move folder => status %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var moved struct {
		FolderId       string `json:"folderId"`
		FolderPath     string `json:"folderPath"`
		ParentFolderId string `json:"parentFolderId"`
	}
	if err := json.Unmarshal(body, &moved); err != nil {
		return fmt.Errorf("decode moveFolder response: %w", err)
	}
	if moved.FolderId == "" {
		return errors.New("move folder => empty folderId in response")
	}

	log.Printf("[moveFolderRecord] success => folderID=%q newParentID=%q => newPath=%q",
		moved.FolderId, moved.ParentFolderId, moved.FolderPath)
	return nil
}

// MoveFolder => moves the folder at oldFolderPath to be a child of the folder at destinationPath
func (h *Helper) MoveFolder(ctx context.Context, oldFolderPath, destinationPath string) error {
	if oldFolderPath == "" {
		return errors.New("MoveFolder: old folder path is empty")
	}
	if destinationPath == "" {
		return errors.New("MoveFolder: destination path is empty")
	}

	token, err := h.fetchJWT(ctx)
	if err != nil {
		return err
	}

	// 2) Look up ID & role of the source folder
	sourceFolderID, sourceRole, err := h.fetchFolderIDAndRole(ctx, oldFolderPath, token)
	if err != nil {
		if errors.Is(err, ErrPermissionDenied) {
			return err
		}
		return fmt.Errorf("MoveFolder: fetchFolderIDAndRole (source) => %w", err)
	}
	if sourceFolderID == "" {
		return ErrPermissionDenied
	}

	// Typically require EDITOR/FULL/OWNER on the source folder
	if sourceRole != "EDITOR" && sourceRole != "FULL" && sourceRole != "OWNER" {
		return ErrPermissionDenied
	}

	// 3) Look up ID & role of the destination folder
	destFolderID, destRole, err := h.fetchFolderIDAndRole(ctx, destinationPath, token)
	if err != nil {
		if errors.Is(err, ErrPermissionDenied) {
			return err
		}
		return fmt.Errorf("MoveFolder: fetchFolderIDAndRole (destination) => %w", err)
	}
	if destFolderID == "" {
		return ErrPermissionDenied
	}

	// Typically require EDITOR/FULL/OWNER on the destination
	if destRole != "EDITOR" && destRole != "FULL" && destRole != "OWNER" {
		return ErrPermissionDenied
	}

	// 4) Do the "move" call
	err = h.moveFolderRecord(ctx, token, sourceFolderID, destFolderID)
	if err != nil {
		return fmt.Errorf("moveFolderRecord => %w", err)
	}
	log.Printf("[MoveFolder] => oldPath=%q => newParentPath=%q => SUCCESS", oldFolderPath, destinationPath)
	return nil
}

// -----------------------------------------------------------------------------
// copyFolderRecord => PATCH /api/folders/{folderId}/copy?destinationFolderId=...
// -----------------------------------------------------------------------------

func (h *Helper) copyFolderRecord(ctx context.Context, token, sourceFolderID, destinationFolderID string) error {
	if sourceFolderID == "" {
		return errors.New("copyFolderRecord: sourceFolderID cannot be empty")
	}
	if destinationFolderID == "" {
		return errors.New("copyFolderRecord: destinationFolderID cannot be empty")
	}

	base := h.opt.DCFolderCopyURL
	if base == "" {
		return errors.New("missing DCFolderCopyURL in config")
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}

	copyURL := fmt.Sprintf("%s%s/copy?destinationFolderId=%s",
		base,
		sourceFolderID,
		url.QueryEscape(destinationFolderID),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, copyURL, nil)
	if err != nil {
		return fmt.Errorf("copyFolderRecord: create PATCH request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("copyFolderRecord: call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("copy folder => status %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var copied struct {
		FolderId       string `json:"folderId"`
		FolderPath     string `json:"folderPath"`
		ParentFolderId string `json:"parentFolderId"`
	}
	if err := json.Unmarshal(body, &copied); err != nil {
		return fmt.Errorf("decode copyFolder response: %w", err)
	}
	if copied.FolderId == "" {
		return errors.New("copy folder => empty folderId in response")
	}

	log.Printf("[copyFolderRecord] success => new folderID=%q path=%q parentID=%q",
		copied.FolderId,
		copied.FolderPath,
		copied.ParentFolderId,
	)
	return nil
}

// CopyFolder => copies the folder at srcFolderPath into the folder at destFolderPath
func (h *Helper) CopyFolder(ctx context.Context, srcFolderPath, destFolderPath string) error {
	if srcFolderPath == "" {
		return errors.New("CopyFolder: srcFolderPath is empty")
	}
	if destFolderPath == "" {
		return errors.New("CopyFolder: destFolderPath is empty")
	}

	token, err := h.fetchJWT(ctx)
	if err != nil {
		return err
	}

	// 1) Look up source folder
	srcID, srcRole, err := h.fetchFolderIDAndRole(ctx, srcFolderPath, token)
	if err != nil {
		if errors.Is(err, ErrPermissionDenied) {
			return err
		}
		return fmt.Errorf("CopyFolder: fetchFolderIDAndRole (source) => %w", err)
	}
	if srcID == "" {
		return ErrPermissionDenied
	}

	// 2) Check user's right to copy *from* the source
	// If you only require "read" permission, you'd check if srcRole != "NONE".
	// Some orgs might require "EDITOR". Adjust to your policy.
	if srcRole == "NONE" {
		return ErrPermissionDenied
	}

	// 3) Look up destination folder
	destID, destRole, err := h.fetchFolderIDAndRole(ctx, destFolderPath, token)
	if err != nil {
		if errors.Is(err, ErrPermissionDenied) {
			return err
		}
		return fmt.Errorf("CopyFolder: fetchFolderIDAndRole (destination) => %w", err)
	}
	if destID == "" {
		return ErrPermissionDenied
	}

	// Typically must have EDITOR/FULL/OWNER in the destination
	if destRole != "EDITOR" && destRole != "FULL" && destRole != "OWNER" {
		return ErrPermissionDenied
	}

	// 4) Do the copy
	err = h.copyFolderRecord(ctx, token, srcID, destID)
	if err != nil {
		return fmt.Errorf("CopyFolder => copyFolderRecord => %w", err)
	}

	log.Printf("[CopyFolder] => from=%q => to=%q => SUCCESS", srcFolderPath, destFolderPath)
	return nil
}

// -----------------------------------------------------------------------------
// CheckPermission => typical usage
// -----------------------------------------------------------------------------

func (h *Helper) CheckPermission(ctx context.Context, action, bucket, folderPath string) error {
	log.Printf("[CheckPermission] => action=%q bucket=%q path=%q", action, bucket, folderPath)

	// If folderPath is empty, we assume top-level with no subfolder.
	// Right now, you "allow root by default".
	if folderPath == "" {
		log.Printf("[CheckPermission] => empty path => allow root by default")
		return nil
	}

	token, err := h.fetchJWT(ctx)
	if err != nil {
		return err
	}

	lcAction := strings.ToLower(action)
	switch lcAction {

	//---------------------------------------------------------------------------
	case "list", "read", "remove":
		// Step 1) Split off the last segment
		parentPath, _ := splitOffLastSegment(folderPath)

		if parentPath == "" {
			// That means the user is referencing something at "top-level" (no parent).
			// We want to allow top-level *folders* but forbid top-level *files*.
			// We'll assume anything recognized by `fetchFolderIDAndRole(folderPath)` is a "folder".
			folderID, role, e := h.fetchFolderIDAndRole(ctx, folderPath, token)
			if e != nil {
				// If the microservice says permission denied or not found => treat it as "no top-level folder"
				if errors.Is(e, ErrPermissionDenied) {
					// Possibly a "top-level file"? => forbid
					return e
				}
				return fmt.Errorf("top-level fetchFolderIDAndRole => %w", e)
			}
			if folderID == "" {
				// We didn't get a folder => forbid
				return ErrPermissionDenied
			}
			// So we have a top-level folder. Now check role
			switch lcAction {
			case "list", "read":
				if role == "NONE" {
					return ErrPermissionDenied
				}
				// else allow
				return nil
			case "remove":
				if role != "EDITOR" && role != "FULL" && role != "OWNER" {
					return ErrPermissionDenied
				}
				return nil
			}
		}

		// If parentPath != "" => normal check: fetch parent's role
		parentFolderID, parentRole, e := h.fetchFolderIDAndRole(ctx, parentPath, token)
		if e != nil {
			if errors.Is(e, ErrPermissionDenied) {
				return e
			}
			return fmt.Errorf("fetch parent folder role: %w", e)
		}
		if parentFolderID == "" {
			return ErrPermissionDenied
		}

		switch lcAction {
		case "list", "read":
			if parentRole == "NONE" {
				return ErrPermissionDenied
			}
		case "remove":
			if parentRole != "EDITOR" && parentRole != "FULL" && parentRole != "OWNER" {
				return ErrPermissionDenied
			}
		}
		return nil

	//---------------------------------------------------------------------------
	case "put", "copy":

		parentPath, _ := splitOffLastSegment(folderPath)
		if parentPath == "" {
			// user is at top-level
			// if the user is calling Mkdir => we want to allow
			// if they're actually uploading a file => do we want to allow or block?
			// ...
			// For simplicity, just always allow for single-segment "folder" creation:
			return nil
		}
		/*
			// If we have a parent path, fetch parent's role
			parentID, parentRole, e := h.fetchFolderIDAndRole(ctx, parentPath, token)
			if e != nil {
				if errors.Is(e, ErrPermissionDenied) {
					return e
				}
				return fmt.Errorf("fetch parent ID/role: %w", e)
			}
			if parentID == "" {
				return ErrPermissionDenied
			}
			if parentRole != "EDITOR" && parentRole != "FULL" && parentRole != "OWNER" {
				return ErrPermissionDenied
			}

			// Optionally auto-create the subfolder record
			//  _, e2 := h.createFolderRecord(ctx, token, parentID, finalSegment, false)
			//  if e2 != nil {
			//    log.Printf("[CheckPermission] => createFolder => error => %v", e2)
			//  return ErrPermissionDenied
			//  }

		*/
		return nil

	//---------------------------------------------------------------------------
	default:
		return ErrPermissionDenied
	}
}
