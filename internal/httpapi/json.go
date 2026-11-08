// JSON request/response helpers for the HTTP API.
package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
)

type errorBody struct {
	Error string `json:"error"`
}

// writeJSON encodes v as application/json with status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error object.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

// readJSON decodes a JSON body into dst (max 1 MiB).
func readJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
