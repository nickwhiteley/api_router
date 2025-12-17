package middleware

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
)

// CompressionMiddleware provides response compression
func CompressionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if client accepts gzip encoding
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		// Check if response should be compressed based on content type
		if !shouldCompress(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Create gzip writer
		gz := gzip.NewWriter(w)
		defer gz.Close()

		// Wrap response writer
		gzw := &gzipResponseWriter{
			ResponseWriter: w,
			Writer:         gz,
		}

		// Set compression headers
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")

		// Serve the request with compression
		next.ServeHTTP(gzw, r)
	})
}

// gzipResponseWriter wraps http.ResponseWriter with gzip compression
type gzipResponseWriter struct {
	http.ResponseWriter
	Writer io.Writer
}

// Write compresses and writes data
func (gzw *gzipResponseWriter) Write(data []byte) (int, error) {
	return gzw.Writer.Write(data)
}

// shouldCompress determines if the request should be compressed
func shouldCompress(r *http.Request) bool {
	// Don't compress if already compressed
	if r.Header.Get("Content-Encoding") != "" {
		return false
	}

	// Compress based on path patterns
	path := r.URL.Path

	// Compress API responses
	if strings.HasPrefix(path, "/api/") {
		return true
	}

	// Compress static assets (except images)
	if strings.HasSuffix(path, ".js") ||
		strings.HasSuffix(path, ".css") ||
		strings.HasSuffix(path, ".html") ||
		strings.HasSuffix(path, ".json") ||
		strings.HasSuffix(path, ".xml") ||
		strings.HasSuffix(path, ".txt") {
		return true
	}

	// Don't compress images, videos, or already compressed files
	if strings.HasSuffix(path, ".jpg") ||
		strings.HasSuffix(path, ".jpeg") ||
		strings.HasSuffix(path, ".png") ||
		strings.HasSuffix(path, ".gif") ||
		strings.HasSuffix(path, ".webp") ||
		strings.HasSuffix(path, ".mp4") ||
		strings.HasSuffix(path, ".zip") ||
		strings.HasSuffix(path, ".gz") {
		return false
	}

	return true
}

// StaticAssetMiddleware provides caching headers for static assets
func StaticAssetMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Set cache headers for static assets
		if isStaticAsset(path) {
			// Cache static assets for 1 hour
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.Header().Set("ETag", generateETag(path))

			// Check if client has cached version
			if r.Header.Get("If-None-Match") == generateETag(path) {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		} else {
			// Don't cache API responses by default
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}

		next.ServeHTTP(w, r)
	})
}

// isStaticAsset determines if the path is a static asset
func isStaticAsset(path string) bool {
	staticExtensions := []string{
		".js", ".css", ".html", ".htm", ".png", ".jpg", ".jpeg", ".gif", ".webp",
		".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf",
	}

	for _, ext := range staticExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}

	return false
}

// generateETag generates a simple ETag for a path
func generateETag(path string) string {
	// In production, this should be based on file modification time or content hash
	return `"` + path + `"`
}
