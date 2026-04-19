package zones

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// AdminHandlers serves the /api/v1/admin/zones CRUD API.
type AdminHandlers struct {
	Store Store
}

// NewAdminHandlers wires an AdminHandlers with the given Store.
func NewAdminHandlers(s Store) *AdminHandlers {
	return &AdminHandlers{Store: s}
}

// List returns every zone.
func (h *AdminHandlers) List(w http.ResponseWriter, r *http.Request) {
	list, err := h.Store.List(r.Context())
	if err != nil {
		internalErr(w, r, err, "list zones")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// Create inserts a new zone. Body: {name, description}. Name is required.
func (h *AdminHandlers) Create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	z, err := h.Store.Create(r.Context(), Zone{Name: body.Name, Description: body.Description})
	if errors.Is(err, ErrConflict) {
		writeErr(w, http.StatusConflict, "zone name already exists")
		return
	}
	if err != nil {
		internalErr(w, r, err, "create zone")
		return
	}
	writeJSON(w, http.StatusCreated, z)
}

// Get returns a single zone by id.
func (h *AdminHandlers) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid zone id")
		return
	}
	z, err := h.Store.Get(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "zone not found")
		return
	}
	if err != nil {
		internalErr(w, r, err, "get zone")
		return
	}
	writeJSON(w, http.StatusOK, z)
}

// Update changes name + description on an existing zone. Body matches Zone.
func (h *AdminHandlers) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid zone id")
		return
	}
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	z, err := h.Store.Update(r.Context(), Zone{ID: id, Name: body.Name, Description: body.Description})
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "zone not found")
		return
	}
	if errors.Is(err, ErrConflict) {
		writeErr(w, http.StatusConflict, "zone name already exists")
		return
	}
	if err != nil {
		internalErr(w, r, err, "update zone")
		return
	}
	writeJSON(w, http.StatusOK, z)
}

// Delete removes a zone by id.
func (h *AdminHandlers) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid zone id")
		return
	}
	err = h.Store.Delete(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "zone not found")
		return
	}
	if err != nil {
		internalErr(w, r, err, "delete zone")
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
// be a short, fixed verb-phrase like "list zones" or "create zone".
func internalErr(w http.ResponseWriter, r *http.Request, err error, op string) {
	// r is accepted for future enrichment (request ID, remote addr)
	// but intentionally unused today to keep the log line stable.
	_ = r
	log.Printf("manageserver/zones: %s: %v", op, err)
	writeErr(w, http.StatusInternalServerError, "internal server error")
}
