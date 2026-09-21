package build

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// downloadMu serialises the progress lines when several downloads run at once.
var downloadMu sync.Mutex

// downloadAttempts bounds the retries of a single transfer.  Every attempt
// resumes the partial file, so a slow or interrupted download still finishes.
const downloadAttempts = 6

// downloadTransport keeps the package transfers on HTTP/1.1: the MikroTik CDN
// is slow from some networks and occasionally cancels HTTP/2 streams
// mid-transfer, which cannot be resumed.
var downloadTransport = &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	ForceAttemptHTTP2:     false,
	MaxIdleConns:          16,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   30 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// downloadClient is used for package and ISO downloads.
var downloadClient = &http.Client{Timeout: 30 * time.Minute, Transport: downloadTransport}

// retryDelay is the pause before attempt n (2..downloadAttempts): 5s, 10s,
// 20s, ... capped at a minute.
func retryDelay(attempt int) time.Duration {
	d := 5 * time.Second << (attempt - 2)
	if d > time.Minute {
		d = time.Minute
	}
	return d
}

// download fetches url into dest unless a verified cache entry exists.
// Transfers land in dest+".part" first so interrupted runs do not leave a
// truncated cache entry behind, and the SHA-256 of the result is recorded in
// dest+".sha256" so a truncated file cannot masquerade as a cache hit.
//
// A failed attempt keeps the partial file and the next attempt continues it
// with a Range request; the same file is resumed when a later run finds the
// .part file again.
func download(url, dest string) error {
	return downloadRetry(url, dest, downloadAttempts, retryDelay)
}

// downloadRetry is download with an explicit attempt bound and delay, so
// tests do not have to wait through the backoff.
func downloadRetry(url, dest string, attempts int, delay func(int) time.Duration) error {
	if cachedDownload(dest) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp := dest + ".part"
	name := filepath.Base(dest)
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			pause := delay(attempt)
			if pause > 0 {
				fmt.Fprintf(os.Stderr, "    %s: attempt %d/%d failed (%v); retrying in %s\n",
					name, attempt-1, attempts, lastErr, pause)
				time.Sleep(pause)
			}
		}
		if err := fetchToFile(url, tmp, name); err != nil {
			lastErr = err
			continue
		}
		sum, err := fileSHA256(tmp)
		if err != nil {
			return err
		}
		if err := os.Rename(tmp, dest); err != nil {
			return err
		}
		// The sidecar is an optimisation: if it cannot be recorded, the file
		// is still usable and the next run trusts it once (see cachedDownload).
		_ = os.WriteFile(dest+".sha256", []byte(sum), 0o644)
		return nil
	}
	return fmt.Errorf("download %s: %w", url, lastErr)
}

// fetchToFile performs one resumable transfer into path.  An existing partial
// file is continued with a Range request; it is left in place when the
// transfer fails so the next attempt can pick up where this one stopped.
func fetchToFile(url, path, name string) error {
	var offset int64
	if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() {
		offset = st.Size()
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	resp, err := downloadClient.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		// The server ignored the range (or there was none): start over.
		offset = 0
		if err := out.Truncate(0); err != nil {
			return err
		}
	case http.StatusPartialContent:
		start, ok := contentRangeStart(resp.Header.Get("Content-Range"))
		if !ok || start != offset {
			return fmt.Errorf("download %s: unexpected Content-Range %q (resuming at %d)",
				url, resp.Header.Get("Content-Range"), offset)
		}
	case http.StatusRequestedRangeNotSatisfiable:
		// The partial file is at least as long as the remote copy (e.g. the
		// transfer finished just before it failed): drop it and start over.
		os.Remove(path)
		return fmt.Errorf("download %s: HTTP 416, partial file discarded", url)
	default:
		return fmt.Errorf("download %s: HTTP %s", url, resp.Status)
	}
	total := resp.ContentLength
	if total >= 0 {
		total += offset
	}
	if _, err := out.Seek(offset, io.SeekStart); err != nil {
		return err
	}

	start := time.Now()
	buf := make([]byte, 1<<20)
	var written int64
	var lastReport time.Time
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return werr
			}
			written += int64(n)
			if time.Since(lastReport) > 2*time.Second {
				lastReport = time.Now()
				rate := float64(written) / time.Since(start).Seconds()
				downloadMu.Lock()
				fmt.Fprintf(os.Stderr, "    %s: %.1f MiB (%.1f MiB/s)\r", name,
					float64(offset+written)/(1<<20), rate/(1<<20))
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
	if total >= 0 && offset+written != total {
		return fmt.Errorf("download %s: truncated (%d of %d bytes)", url, offset+written, total)
	}
	if written == 0 && offset == 0 {
		return fmt.Errorf("download %s: empty response", url)
	}
	if err := out.Close(); err != nil {
		return err
	}
	downloadMu.Lock()
	fmt.Fprintf(os.Stderr, "    %s: %.1f MiB\n", name, float64(offset+written)/(1<<20))
	downloadMu.Unlock()
	return nil
}

// contentRangeStart returns the first byte offset of a Content-Range header
// ("bytes 100-199/500").
func contentRangeStart(header string) (int64, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(header), "bytes ")
	if !ok {
		return 0, false
	}
	rangePart, _, ok := strings.Cut(rest, "/")
	if !ok {
		return 0, false
	}
	first, _, ok := strings.Cut(rangePart, "-")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(first), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
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
