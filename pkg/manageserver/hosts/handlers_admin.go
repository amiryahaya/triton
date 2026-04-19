package hosts

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// AdminHandlers serves the /api/v1/admin/hosts CRUD API.
type AdminHandlers struct {
	Store Store
}

// NewAdminHandlers wires an AdminHandlers with the given Store.
func NewAdminHandlers(s Store) *AdminHandlers {
	return &AdminHandlers{Store: s}
}

// hostRequestBody is the JSON shape accepted by Create/Update/BulkCreate.
// Keeping it separate from the Host model prevents clients from forging
// server-managed fields (ID, CreatedAt, UpdatedAt).
type hostRequestBody struct {
	Hostname   string     `json:"hostname"`
	IP         string     `json:"ip"`
	ZoneID     *uuid.UUID `json:"zone_id"`
	OS         string     `json:"os"`
	LastSeenAt *time.Time `json:"last_seen_at"`
}

// toHost converts a request body into a Host without any server-managed
// fields.
func (b hostRequestBody) toHost() Host {
	return Host{
		Hostname:   strings.TrimSpace(b.Hostname),
		IP:         strings.TrimSpace(b.IP),
		ZoneID:     b.ZoneID,
		OS:         b.OS,
		LastSeenAt: b.LastSeenAt,
	}
}

// List returns every host, or hosts filtered by ?zone_id=<uuid>.
func (h *AdminHandlers) List(w http.ResponseWriter, r *http.Request) {
	if zoneStr := r.URL.Query().Get("zone_id"); zoneStr != "" {
		zoneID, err := uuid.Parse(zoneStr)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid zone_id")
			return
		}
		list, err := h.Store.ListByZone(r.Context(), zoneID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, list)
		return
	}

	list, err := h.Store.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// Create inserts a single host. Body: {hostname, ip?, zone_id?, os?, last_seen_at?}.
func (h *AdminHandlers) Create(w http.ResponseWriter, r *http.Request) {
	var body hostRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	host := body.toHost()
	if host.Hostname == "" {
		writeErr(w, http.StatusBadRequest, "hostname is required")
		return
	}
	created, err := h.Store.Create(r.Context(), host)
	if errors.Is(err, ErrConflict) {
		writeErr(w, http.StatusConflict, "hostname already exists")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

// Get returns a single host by id.
func (h *AdminHandlers) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid host id")
		return
	}
	host, err := h.Store.Get(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, host)
}

// Update changes host fields. Body shape matches hostRequestBody.
func (h *AdminHandlers) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid host id")
		return
	}
	var body hostRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	host := body.toHost()
	host.ID = id
	updated, err := h.Store.Update(r.Context(), host)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "host not found")
		return
	}
	if errors.Is(err, ErrConflict) {
		writeErr(w, http.StatusConflict, "hostname already exists")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// Delete removes a host by id.
func (h *AdminHandlers) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid host id")
		return
	}
	err = h.Store.Delete(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// BulkCreate inserts a batch of hosts in a single transaction. Any
// hostname collision rolls back the entire batch (all-or-nothing).
// Body: {"hosts": [{hostname, ip?, zone_id?, os?}, ...]}
func (h *AdminHandlers) BulkCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Hosts []hostRequestBody `json:"hosts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(body.Hosts) == 0 {
		writeErr(w, http.StatusBadRequest, "hosts array is required and must be non-empty")
		return
	}
	batch := make([]Host, 0, len(body.Hosts))
	for i, row := range body.Hosts {
		host := row.toHost()
		if host.Hostname == "" {
			writeErr(w, http.StatusBadRequest, "hostname is required (index "+strconv.Itoa(i)+")")
			return
		}
		batch = append(batch, host)
	}
	out, err := h.Store.BulkCreate(r.Context(), batch)
	if errors.Is(err, ErrConflict) {
		writeErr(w, http.StatusConflict, "hostname already exists in batch")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"hosts": out})
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
