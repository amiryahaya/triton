package tags

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/internal/limits"
)

var hexColorRE = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)

// AdminHandlers serves the /api/v1/admin/tags CRUD API.
type AdminHandlers struct {
	Store Store
}

// NewAdminHandlers wires an AdminHandlers with the given Store.
func NewAdminHandlers(s Store) *AdminHandlers {
	return &AdminHandlers{Store: s}
}

// tagRequestBody is the JSON shape accepted by Create and Update.
// Keeping it separate from Tag prevents clients from forging
// server-managed fields (ID, HostCount, CreatedAt).
type tagRequestBody struct {
	Name  string `json:"name"`
	Color string `json:"color"`
}

// validate checks handler-layer invariants before the tag reaches the
// store: name is required, and color must be a 6-digit hex string.
func (b tagRequestBody) validate() error {
	if strings.TrimSpace(b.Name) == "" {
		return errors.New("name is required")
	}
	if !hexColorRE.MatchString(b.Color) {
		return errors.New("color must be a 6-digit hex color (e.g. #3B82F6)")
	}
	return nil
}

// List returns every tag.
func (h *AdminHandlers) List(w http.ResponseWriter, r *http.Request) {
	list, err := h.Store.List(r.Context())
	if err != nil {
		internalErr(w, r, err, "list tags")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// Create inserts a new tag. Body: {name, color}. Both fields are required.
func (h *AdminHandlers) Create(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, limits.MaxRequestBody)

	var body tagRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := body.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	tag, err := h.Store.Create(r.Context(), Tag{
		Name:  strings.TrimSpace(body.Name),
		Color: body.Color,
	})
	if errors.Is(err, ErrConflict) {
		writeErr(w, http.StatusConflict, "tag name already exists")
		return
	}
	if err != nil {
		internalErr(w, r, err, "create tag")
		return
	}
	writeJSON(w, http.StatusCreated, tag)
}

// Update changes name + color on an existing tag.
func (h *AdminHandlers) Update(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, limits.MaxRequestBody)

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid tag id")
		return
	}
	var body tagRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := body.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	tag, err := h.Store.Update(r.Context(), Tag{
		ID:    id,
		Name:  strings.TrimSpace(body.Name),
		Color: body.Color,
	})
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "tag not found")
		return
	}
	if errors.Is(err, ErrConflict) {
		writeErr(w, http.StatusConflict, "tag name already exists")
		return
	}
	if err != nil {
		internalErr(w, r, err, "update tag")
		return
	}
	writeJSON(w, http.StatusOK, tag)
}

// Delete removes a tag by id.
func (h *AdminHandlers) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid tag id")
		return
	}
	if err := h.Store.Delete(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeErr(w, http.StatusNotFound, "tag not found")
			return
		}
		internalErr(w, r, err, "delete tag")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeErr writes a JSON error body {"error": msg} with the given status.
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// internalErr logs the underlying error with operation context and
// writes a generic 500 response body to the client. This prevents
// pgx / Postgres error strings (table names, constraint names, DSN
// hints) from leaking through the wire. Caller-supplied op should
// be a short, fixed verb-phrase like "list tags" or "create tag".
// Request method + path are included so grep-ing server logs for a
// specific op lands you on the HTTP request without correlation
// tooling.
func internalErr(w http.ResponseWriter, r *http.Request, err error, op string) {
	log.Printf("manageserver/tags: %s: %s %s: %v", op, r.Method, r.URL.Path, err)
	writeErr(w, http.StatusInternalServerError, "internal server error")
}
