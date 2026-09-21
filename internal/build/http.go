package build

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// downloadMu serialises the progress lines when several downloads run at once.
var downloadMu sync.Mutex

// download fetches url into dest unless a verified cache entry exists.
// Downloads land in a temporary file first so interrupted runs do not leave a
// truncated cache entry behind, and the SHA-256 of the result is recorded in
// dest+".sha256" so a truncated file cannot masquerade as a cache hit.
func download(url, dest string) error {
	if cachedDownload(dest) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp := dest + ".part"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	defer func() {
		out.Close()
		os.Remove(tmp)
	}()
	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %s", url, resp.Status)
	}
	start := time.Now()
	hasher := sha256.New()
	buf := make([]byte, 1<<20)
	var total int64
	var lastReport time.Time
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return werr
			}
			hasher.Write(buf[:n])
			total += int64(n)
			if time.Since(lastReport) > 2*time.Second {
				lastReport = time.Now()
				rate := float64(total) / time.Since(start).Seconds()
				downloadMu.Lock()
				fmt.Fprintf(os.Stderr, "    %s: %.1f MiB (%.1f MiB/s)\r", filepath.Base(dest),
					float64(total)/(1<<20), rate/(1<<20))
				downloadMu.Unlock()
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("download %s: %w", url, err)
		}
	}
	if resp.ContentLength >= 0 && total != resp.ContentLength {
		return fmt.Errorf("download %s: truncated (%d of %d bytes)", url, total, resp.ContentLength)
	}
	if total == 0 {
		return fmt.Errorf("download %s: empty response", url)
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return err
	}
	// The sidecar is an optimisation: if it cannot be recorded, the file is
	// still usable and the next run trusts it once (see cachedDownload).
	_ = os.WriteFile(dest+".sha256", []byte(hex.EncodeToString(hasher.Sum(nil))), 0o644)
	downloadMu.Lock()
	fmt.Fprintf(os.Stderr, "    %s: %.1f MiB\n", filepath.Base(dest), float64(total)/(1<<20))
	downloadMu.Unlock()
	return nil
}

// cachedDownload reports whether dest holds a complete previous download.  A
// cache entry without a checksum sidecar is trusted once (caches from before
// the sidecar existed) and gets its checksum recorded for later runs; an entry
// whose recorded checksum does not match is re-downloaded.
func cachedDownload(dest string) bool {
	st, err := os.Stat(dest)
	if err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
		return false
	}
	sum, err := fileSHA256(dest)
	if err != nil {
		return false
	}
	recorded, err := os.ReadFile(dest + ".sha256")
	if err != nil {
		_ = os.WriteFile(dest+".sha256", []byte(sum), 0o644)
		return true
	}
	return strings.EqualFold(strings.TrimSpace(string(recorded)), sum)
}

// fileSHA256 returns the hex SHA-256 of a file.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// fetchString downloads a small text file and returns its contents.
func fetchString(url string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: HTTP %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return string(data), nil
}
