package hosts

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// HostCapGuard is the narrow licence-guard surface the hosts admin
// handler consults before persisting a new Host. Kept minimal so
// tests can inject a one-method fake without constructing a real
// *license.Guard.
//
// A nil Guard on AdminHandlers means "no licence configured" — cap
// check is skipped entirely (unlimited). LimitCap returning -1 for a
// metric means the same thing.
type HostCapGuard interface {
	LimitCap(metric, window string) int64
}

// AdminHandlers serves the /api/v1/admin/hosts CRUD API.
type AdminHandlers struct {
	Store Store
	Guard HostCapGuard
}

// NewAdminHandlers wires an AdminHandlers with the given Store and
// (optional) Guard. Passing a nil Guard disables licence-cap
// enforcement — useful in tests that exercise the store layer only.
func NewAdminHandlers(s Store, guard HostCapGuard) *AdminHandlers {
	return &AdminHandlers{Store: s, Guard: guard}
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

// validateHost checks the handler-layer invariants that must hold before
// the Host reaches the store: hostname is required, and if an IP is
// supplied it must parse. Callers should have already applied toHost()
// so whitespace is trimmed.
//
// Keeping this above the store boundary means malformed input never
// reaches Postgres, so clients see a clean 400 instead of a 500 with
// leaked pg error text.
func validateHost(h Host) error {
	if h.Hostname == "" {
		return errors.New("hostname is required")
	}
	if h.IP != "" {
		if ip := net.ParseIP(h.IP); ip == nil {
			return fmt.Errorf("invalid ip address %q", h.IP)
		}
	}
	return nil
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
			internalErr(w, r, err, "list hosts by zone")
			return
		}
		writeJSON(w, http.StatusOK, list)
		return
	}

	list, err := h.Store.List(r.Context())
	if err != nil {
		internalErr(w, r, err, "list hosts")
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
	if err := validateHost(host); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// Licence host cap. Checked before the INSERT so a rejected Create
	// never mutates state. We read Count() directly (no transactional
	// guard around Count+Insert) because a licence cap overshoot by 1
	// row under concurrent inserts is acceptable — the usage-pusher
	// will surface the overshoot in the next tick.
	if h.Guard != nil {
		if cap := h.Guard.LimitCap("hosts", "total"); cap >= 0 {
			c, err := h.Store.Count(r.Context())
			if err != nil {
				internalErr(w, r, err, "count hosts for cap")
				return
			}
			if c+1 > cap {
				writeErr(w, http.StatusForbidden,
					fmt.Sprintf("licence host cap exceeded (have %d, cap %d)", c, cap))
				return
			}
		}
	}

	created, err := h.Store.Create(r.Context(), host)
	if errors.Is(err, ErrConflict) {
		writeErr(w, http.StatusConflict, "hostname already exists")
		return
	}
	if errors.Is(err, ErrInvalidInput) {
		writeErr(w, http.StatusBadRequest, "invalid host input")
		return
	}
	if err != nil {
		internalErr(w, r, err, "create host")
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
		internalErr(w, r, err, "get host")
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
	if err := validateHost(host); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := h.Store.Update(r.Context(), host)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "host not found")
		return
	}
	if errors.Is(err, ErrConflict) {
		writeErr(w, http.StatusConflict, "hostname already exists")
		return
	}
	if errors.Is(err, ErrInvalidInput) {
		writeErr(w, http.StatusBadRequest, "invalid host input")
		return
	}
	if err != nil {
		internalErr(w, r, err, "update host")
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
		internalErr(w, r, err, "delete host")
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
		if err := validateHost(host); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error()+" (index "+strconv.Itoa(i)+")")
			return
		}
		batch = append(batch, host)
	}

	// Licence host cap. The bulk form rejects with a shortfall-aware
	// error so operators see exactly how many rows the batch exceeds
	// the cap by — matches the UX the admin UI wants when it surfaces
	// the 403 back to the user.
	if h.Guard != nil {
		if cap := h.Guard.LimitCap("hosts", "total"); cap >= 0 {
			c, err := h.Store.Count(r.Context())
			if err != nil {
				internalErr(w, r, err, "count hosts for cap")
				return
			}
			needed := int64(len(batch))
			if c+needed > cap {
				writeErr(w, http.StatusForbidden, fmt.Sprintf(
					"licence host cap exceeded (have %d, cap %d, requested %d)",
					c, cap, needed))
				return
			}
		}
	}

	out, err := h.Store.BulkCreate(r.Context(), batch)
	if errors.Is(err, ErrConflict) {
		writeErr(w, http.StatusConflict, "hostname already exists in batch")
		return
	}
	if errors.Is(err, ErrInvalidInput) {
		writeErr(w, http.StatusBadRequest, "invalid host input in batch")
		return
	}
	if err != nil {
		internalErr(w, r, err, "bulk create hosts")
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

// internalErr logs the underlying error with operation context and
// writes a generic 500 response body to the client. This prevents
// pgx / Postgres error strings (table names, constraint names, DSN
// hints) from leaking through the wire. Caller-supplied op should
// be a short, fixed verb-phrase like "list hosts" or "bulk create hosts".
// Request method + path are included so grep-ing server logs for a
// specific op lands you on the HTTP request without correlation
// tooling.
func internalErr(w http.ResponseWriter, r *http.Request, err error, op string) {
	log.Printf("manageserver/hosts: %s: %s %s: %v", op, r.Method, r.URL.Path, err)
	writeErr(w, http.StatusInternalServerError, "internal server error")
}
