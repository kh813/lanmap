package updater

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const GitHubRepo = "kh813/lanmap"

// ReleaseInfo represents the latest GitHub release metadata
type ReleaseInfo struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	PublishedAt time.Time `json:"published_at"`
	AssetURL    string    `json:"asset_url"`
	AssetName   string    `json:"asset_name"`
	IsNewer     bool      `json:"is_newer"`
}

type gitHubRelease struct {
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	Body        string        `json:"body"`
	PublishedAt time.Time     `json:"published_at"`
	Assets      []gitHubAsset `json:"assets"`
}

type gitHubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// CheckLatestRelease queries GitHub Releases API for the newest available version
func CheckLatestRelease(currentVersion string) (*ReleaseInfo, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", GitHubRepo)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "lanmap-updater/"+currentVersion)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	var ghRel gitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&ghRel); err != nil {
		return nil, fmt.Errorf("failed to decode GitHub release json: %w", err)
	}

	expectedAsset := getExpectedAssetName()
	var matchingAsset *gitHubAsset
	for _, a := range ghRel.Assets {
		if a.Name == expectedAsset {
			matchingAsset = &a
			break
		}
	}

	info := &ReleaseInfo{
		TagName:     ghRel.TagName,
		Name:        ghRel.Name,
		Body:        ghRel.Body,
		PublishedAt: ghRel.PublishedAt,
		IsNewer:     IsVersionNewer(ghRel.TagName, currentVersion),
	}

	if matchingAsset != nil {
		info.AssetURL = matchingAsset.BrowserDownloadURL
		info.AssetName = matchingAsset.Name
	}

	return info, nil
}

// IsVersionNewer returns true if remoteVersion > currentVersion
func IsVersionNewer(remote, current string) bool {
	rParts := parseVersion(remote)
	cParts := parseVersion(current)

	for i := 0; i < len(rParts) && i < len(cParts); i++ {
		if rParts[i] > cParts[i] {
			return true
		} else if rParts[i] < cParts[i] {
			return false
		}
	}
	return len(rParts) > len(cParts)
}

func parseVersion(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	var result []int
	for _, p := range parts {
		// Strip any build suffix like -beta or -rc
		if idx := strings.IndexAny(p, "-+"); idx != -1 {
			p = p[:idx]
		}
		num, err := strconv.Atoi(p)
		if err == nil {
			result = append(result, num)
		} else {
			result = append(result, 0)
		}
	}
	return result
}

func getExpectedAssetName() string {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	switch goos {
	case "darwin":
		if goarch == "arm64" {
			return "lanmap-mac-arm64.zip"
		}
		return "lanmap-mac-x64.zip"
	case "linux":
		if goarch == "arm64" {
			return "lanmap-linux-arm64.zip"
		}
		return "lanmap-linux-x64.zip"
	case "windows":
		if goarch == "arm64" {
			return "lanmap-win-arm64.zip"
		}
		return "lanmap-win-x64.zip"
	default:
		return fmt.Sprintf("lanmap-%s-%s.zip", goos, goarch)
	}
}

// DownloadAndApplyUpdate downloads the ZIP asset, extracts the binary, and replaces the running executable
func DownloadAndApplyUpdate(assetURL string) error {
	if assetURL == "" {
		return fmt.Errorf("no asset download URL provided")
	}

	// 1. Download zip archive
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", assetURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create download request: %w", err)
	}
	req.Header.Set("User-Agent", "lanmap-updater")

	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download server returned HTTP %d", resp.StatusCode)
	}

	zipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read zip payload: %w", err)
	}

	// 2. Extract executable from zip
	zipReader, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return fmt.Errorf("invalid zip archive: %w", err)
	}

	targetBinaryName := "lanmap"
	if runtime.GOOS == "windows" {
		targetBinaryName = "lanmap.exe"
	}

	var newBinaryBytes []byte
	for _, f := range zipReader.File {
		if f.Name == targetBinaryName || filepath.Base(f.Name) == targetBinaryName {
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("failed to open file in zip: %w", err)
			}
			newBinaryBytes, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return fmt.Errorf("failed to read binary from zip: %w", err)
			}
			break
		}
	}

	if len(newBinaryBytes) == 0 {
		return fmt.Errorf("binary %s not found in downloaded zip archive", targetBinaryName)
	}

	// 3. Locate current executable path
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get running executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlink for executable: %w", err)
	}

	execDir := filepath.Dir(execPath)
	tempPath := filepath.Join(execDir, fmt.Sprintf(".lanmap_update_%d", time.Now().UnixNano()))

	// 4. Write new binary with executable permissions
	if err := os.WriteFile(tempPath, newBinaryBytes, 0755); err != nil {
		return fmt.Errorf("failed to write new binary to temp file (%s): %w", tempPath, err)
	}

	// Ensure permissions
	_ = os.Chmod(tempPath, 0755)

	// 5. Atomic replacement
	if runtime.GOOS == "windows" {
		oldPath := execPath + ".old"
		_ = os.Remove(oldPath) // remove previous .old if any
		if err := os.Rename(execPath, oldPath); err != nil {
			_ = os.Remove(tempPath)
			return fmt.Errorf("windows rename exec->old failed: %w", err)
		}
		if err := os.Rename(tempPath, execPath); err != nil {
			_ = os.Rename(oldPath, execPath) // rollback
			return fmt.Errorf("windows rename temp->exec failed: %w", err)
		}
	} else {
		// Unix / Linux / macOS: Rename temp over exec is atomic even if running
		if err := os.Rename(tempPath, execPath); err != nil {
			_ = os.Remove(tempPath)
			return fmt.Errorf("atomic binary replacement failed: %w", err)
		}
	}

	return nil
}

// RestartSelf spawns the newly replaced binary and cleanly exits the current process
func RestartSelf() error {
	execPath, err := os.Executable()
	if err != nil {
		return err
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return err
	}

	cmd := exec.Command(execPath, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = os.Environ()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to spawn updated process: %w", err)
	}

	// Exit current process in background after slight delay so HTTP response completes
	go func() {
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()

	return nil
}
