package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/server"
)

// AuditRecorder is the narrow hook used by inventory handlers to emit
// audit events. Implemented by pkg/server.Server in Task 10; tests pass
// a no-op or capturing fake. Handlers tolerate a nil recorder.
type AuditRecorder interface {
	Record(ctx context.Context, event, subject string, fields map[string]any)
}

type Handlers struct {
	Store Store
	Audit AuditRecorder
}

func NewHandlers(s Store, a AuditRecorder) *Handlers {
	return &Handlers{Store: s, Audit: a}
}

// --- helpers ---

func (h *Handlers) claims(r *http.Request) (orgID, userID uuid.UUID, ok bool) {
	c := server.ClaimsFromContext(r.Context())
	if c == nil {
		return uuid.Nil, uuid.Nil, false
	}
	var err error
	orgID, err = uuid.Parse(c.Org)
	if err != nil {
		return uuid.Nil, uuid.Nil, false
	}
	userID, err = uuid.Parse(c.Sub)
	if err != nil {
		return uuid.Nil, uuid.Nil, false
	}
	return orgID, userID, true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func parseIDParam(r *http.Request) (uuid.UUID, error) {
	return uuid.Parse(chi.URLParam(r, "id"))
}

func (h *Handlers) audit(ctx context.Context, event, subject string, fields map[string]any) {
	if h.Audit == nil {
		return
	}
	h.Audit.Record(ctx, event, subject, fields)
}

// --- Group handlers ---

type groupPayload struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

func (h *Handlers) CreateGroup(w http.ResponseWriter, r *http.Request) {
	orgID, userID, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid claims")
		return
	}
	var p groupPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(p.Name) == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	g := Group{
		ID:          uuid.Must(uuid.NewV7()),
		OrgID:       orgID,
		Name:        p.Name,
		Description: p.Description,
		CreatedBy:   userID,
	}
	created, err := h.Store.CreateGroup(r.Context(), g)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r.Context(), EventGroupCreate, created.ID.String(), map[string]any{"name": created.Name})
	writeJSON(w, http.StatusCreated, created)
}

func (h *Handlers) ListGroups(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid claims")
		return
	}
	list, err := h.Store.ListGroups(r.Context(), orgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (h *Handlers) GetGroup(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid claims")
		return
	}
	id, err := parseIDParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	g, err := h.Store.GetGroup(r.Context(), orgID, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (h *Handlers) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid claims")
		return
	}
	id, err := parseIDParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var p groupPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(p.Name) == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	updated, err := h.Store.UpdateGroup(r.Context(), orgID, id, p.Name, p.Description)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	h.audit(r.Context(), EventGroupUpdate, updated.ID.String(), map[string]any{"name": updated.Name})
	writeJSON(w, http.StatusOK, updated)
}

func (h *Handlers) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid claims")
		return
	}
	id, err := parseIDParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.Store.DeleteGroup(r.Context(), orgID, id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r.Context(), EventGroupDelete, id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- Host handlers ---

type hostPayload struct {
	GroupID  string `json:"group_id"`
	Hostname string `json:"hostname,omitempty"`
	Address  string `json:"address,omitempty"`
	OS       string `json:"os,omitempty"`
	Mode     string `json:"mode,omitempty"`
	Tags     []Tag  `json:"tags,omitempty"`
}

type hostPatchPayload struct {
	GroupID  *string `json:"group_id,omitempty"`
	Hostname *string `json:"hostname,omitempty"`
	OS       *string `json:"os,omitempty"`
	Mode     *string `json:"mode,omitempty"`
	Tags     *[]Tag  `json:"tags,omitempty"`
}

func (h *Handlers) CreateHost(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid claims")
		return
	}
	var p hostPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	groupID, err := uuid.Parse(p.GroupID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "group_id is required and must be a UUID")
		return
	}
	mode := p.Mode
	if mode == "" {
		mode = "agentless"
	}
	host := Host{
		ID:       uuid.Must(uuid.NewV7()),
		OrgID:    orgID,
		GroupID:  groupID,
		Hostname: p.Hostname,
		OS:       p.OS,
		Mode:     mode,
	}
	if p.Address != "" {
		ip := net.ParseIP(p.Address)
		if ip == nil {
			writeErr(w, http.StatusBadRequest, "address is not a valid IP")
			return
		}
		host.Address = ip
	}
	created, err := h.Store.CreateHost(r.Context(), host)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(p.Tags) > 0 {
		if err := h.Store.SetTags(r.Context(), created.ID, p.Tags); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		created.Tags = p.Tags
	}
	h.audit(r.Context(), EventHostCreate, created.ID.String(), map[string]any{
		"hostname": created.Hostname, "group_id": created.GroupID.String(),
	})
	writeJSON(w, http.StatusCreated, created)
}

func (h *Handlers) ListHosts(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid claims")
		return
	}
	filters := HostFilters{
		OS:   r.URL.Query().Get("os"),
		Mode: r.URL.Query().Get("mode"),
	}
	if g := r.URL.Query().Get("group_id"); g != "" {
		gid, err := uuid.Parse(g)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid group_id filter")
			return
		}
		filters.GroupID = &gid
	}
	list, err := h.Store.ListHosts(r.Context(), orgID, filters)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (h *Handlers) GetHost(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid claims")
		return
	}
	id, err := parseIDParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	host, err := h.Store.GetHost(r.Context(), orgID, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, host)
}

func (h *Handlers) UpdateHost(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid claims")
		return
	}
	id, err := parseIDParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var p hostPatchPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	patch := HostPatch{
		Hostname: p.Hostname,
		OS:       p.OS,
		Mode:     p.Mode,
	}
	if p.GroupID != nil {
		gid, err := uuid.Parse(*p.GroupID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid group_id")
			return
		}
		patch.GroupID = &gid
	}
	updated, err := h.Store.UpdateHost(r.Context(), orgID, id, patch)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if p.Tags != nil {
		if err := h.Store.SetTags(r.Context(), updated.ID, *p.Tags); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		updated.Tags = *p.Tags
	}
	h.audit(r.Context(), EventHostUpdate, updated.ID.String(), nil)
	writeJSON(w, http.StatusOK, updated)
}

func (h *Handlers) DeleteHost(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid claims")
		return
	}
	id, err := parseIDParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.Store.DeleteHost(r.Context(), orgID, id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r.Context(), EventHostDelete, id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

// Ensure errors.Is import stays used if future edits drop it.
var _ = errors.Is
