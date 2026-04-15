package inventory

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/server"
)

// ImportRow is one row in a CSV-derived import request. The CSV parser
// lives client-side; this package only sees the structured JSON.
type ImportRow struct {
	Hostname string `json:"hostname"`
	Address  string `json:"address"`
	OS       string `json:"os"`
	Mode     string `json:"mode"`
	Tags     []Tag  `json:"tags,omitempty"`
}

// ImportRequest is the POST /hosts/import body.
type ImportRequest struct {
	GroupID uuid.UUID   `json:"group_id"`
	Rows    []ImportRow `json:"rows"`
	DryRun  bool        `json:"dry_run"`
}

// ImportError reports a per-row failure during host import.
// Row is 1-based (matches spreadsheet row numbering; the header row
// is excluded by the client-side parser before submission).
type ImportError struct {
	Row   int    `json:"row"`
	Error string `json:"error"`
}

// ImportResponse is the handler's summary.
type ImportResponse struct {
	Accepted   int           `json:"accepted"`
	Rejected   int           `json:"rejected"`
	Duplicates int           `json:"duplicates"`
	Errors     []ImportError `json:"errors,omitempty"`
	DryRun     bool          `json:"dry_run"`
}

// ImportResult is the store-layer return shape (no JSON tags —
// handlers translate to ImportResponse).
type ImportResult struct {
	Accepted   int
	Rejected   int
	Duplicates int
	Errors     []ImportError
}

// maxImportRows caps a single import to keep the SAVEPOINT-per-row
// transaction bounded. UI should batch beyond this.
const maxImportRows = 10000

// ImportHosts handles POST /hosts/import. The group must belong to the
// caller's org; rows are inserted one-by-one with SAVEPOINTs so a
// single duplicate/constraint error does not abort the whole batch.
// With dry_run=true the transaction is rolled back — the counts are
// still returned so the UI can preview.
func (h *Handlers) ImportHosts(w http.ResponseWriter, r *http.Request) {
	var req ImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Rows) == 0 {
		writeErr(w, http.StatusBadRequest, "rows required")
		return
	}
	if len(req.Rows) > maxImportRows {
		writeErr(w, http.StatusBadRequest, "max 10000 rows per import")
		return
	}

	claims := server.ClaimsFromContext(r.Context())
	if claims == nil {
		writeErr(w, http.StatusUnauthorized, "missing or invalid claims")
		return
	}
	orgID, err := uuid.Parse(claims.Org)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid org claim")
		return
	}

	if _, err := h.Store.GetGroup(r.Context(), orgID, req.GroupID); err != nil {
		writeErr(w, http.StatusNotFound, "group not found in org")
		return
	}

	res, err := h.Store.ImportHosts(r.Context(), orgID, req.GroupID, req.Rows, req.DryRun)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	if !req.DryRun {
		h.audit(r.Context(), "inventory.hosts.import", req.GroupID.String(),
			map[string]any{"accepted": res.Accepted, "rejected": res.Rejected, "duplicates": res.Duplicates})
	}

	writeJSON(w, http.StatusOK, ImportResponse{
		Accepted:   res.Accepted,
		Rejected:   res.Rejected,
		Duplicates: res.Duplicates,
		Errors:     res.Errors,
		DryRun:     req.DryRun,
	})
}
