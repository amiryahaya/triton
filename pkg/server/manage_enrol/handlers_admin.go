package manage_enrol

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// manageCertValidity is the lifetime of a `manage:` client leaf. Matches
// the engine leaf cadence — manual rotation via re-running /setup/license
// is a once-a-year ops chore, not a hot-path concern.
const manageCertValidity = 365 * 24 * time.Hour

// ErrCANotBootstrapped is the sentinel handlers_admin returns when the
// configured OrgID has no CA row. Callers test equality rather than
// importing engine.ErrCANotFound; the handler package's contract is
// intentionally narrow.
var ErrCANotBootstrapped = errors.New("manage_enrol: CA not bootstrapped")

// CAProvider is the narrow surface EnrolHandlers needs from the Report-
// side engine CA subsystem. Defining it here (rather than importing
// engine.Store) breaks the cyclic import chain
// pkg/server → manage_enrol → engine → pkg/server.
//
// Production wiring hands a tiny adapter that proxies to engine.Store
// + CA.SignLeaf; tests can drop in an in-memory implementation.
type CAProvider interface {
	// LoadCACert returns the PEM-encoded CA certificate chunk that gets
	// embedded into the enrolment bundle as ca.crt. Returns
	// ErrCANotBootstrapped if the CA has not been generated yet.
	LoadCACert(ctx context.Context) ([]byte, error)

	// SignLeaf mints a ClientAuth leaf signed under the CA. cn, validity,
	// and pub are forwarded unchanged to the CA's SignLeaf method. Returns
	// the PEM-encoded signed leaf.
	SignLeaf(ctx context.Context, cn string, validity time.Duration, pub crypto.PublicKey) ([]byte, error)
}

// EnrolFeatures is the minimal shape the license validator returns. Only
// fields the handler actually reads are listed; the licence server's
// response may carry more, which the validator silently drops.
type EnrolFeatures struct {
	Manage bool
}

// LicenseValidator abstracts the licence-feature check. Production impls
// will call the License Server; tests inject a stub. Returning an
// explicit tenantID keeps the handler agnostic of how the validator maps
// licence → tenant.
type LicenseValidator interface {
	// Validate returns the licence's feature flags, the tenant UUID string
	// associated with the licence (or "" for single-tenant), and an error
	// for hard failures (network, signature, revoked). Missing
	// features.manage is NOT an error here — the handler inspects
	// Features.Manage and returns 403 itself so tests can distinguish
	// "licence rejected" from "feature not granted".
	Validate(ctx context.Context, licenseKey string) (EnrolFeatures, string, error)
}

// EnrolHandlers serves POST /api/v1/admin/enrol/manage — the Report-side
// endpoint Manage calls during /setup/license to mint its mTLS bundle.
type EnrolHandlers struct {
	// CA provides the loader + signer backing this deployment's manage
	// enrolment CA. In production this is a thin adapter around
	// engine.Store (see manage_enrol.NewEngineCAProvider). The narrow
	// interface keeps pkg/server's import graph acyclic.
	CA CAProvider

	// ManageStore persists the issued enrolment. GetByCertSerial is what the
	// mTLS middleware calls on every request once Manage connects.
	ManageStore Store

	// ReportPublicURL is baked into the bundle's config.yaml as
	// `report_url`. Typically the Report's public HTTPS URL (e.g.
	// "https://reports.example.com").
	ReportPublicURL string

	// LicenseClient validates the presented licence + looks up its tenant
	// attribution. Implementations may call LS online or consult a cached
	// token.
	LicenseClient LicenseValidator
}

// enrolRequest is the wire format POSTed by Manage's /setup/license handler.
type enrolRequest struct {
	ManageInstanceID string `json:"manage_instance_id"`
	LicenseKey       string `json:"license_key"`
	PublicKeyPEM     string `json:"public_key_pem"`
}

// Enrol is the HTTP handler. It:
//  1. validates the licence (features.manage must be true);
//  2. parses the caller-provided public key PEM;
//  3. loads the engine CA for h.OrgID;
//  4. mints a `manage:<licHash>:<instanceID>` leaf with 1y validity;
//  5. inserts a manage_instances row keyed by the leaf's serial number;
//  6. streams back a gzipped tar bundle with client.crt, ca.crt, config.yaml.
//
// The request body is capped at 64 KiB — the largest expected field is the
// PEM public key (~500 bytes) and a small cap cheaply bounds denial-of-
// service via oversized JSON.
func (h *EnrolHandlers) Enrol(w http.ResponseWriter, r *http.Request) {
	// Guard required dependencies up-front so an operator-misconfigured
	// handler returns a clean 500 instead of panicking on a nil-pointer
	// deref inside CA or Store calls. LicenseClient has its own check
	// further down (kept there so the tests' "licence validator not
	// configured" string stays stable).
	if h.CA == nil {
		writeErr(w, http.StatusInternalServerError, "CA provider not configured")
		return
	}
	if h.ManageStore == nil {
		writeErr(w, http.StatusInternalServerError, "manage store not configured")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)

	var req enrolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	instanceID, err := uuid.Parse(strings.TrimSpace(req.ManageInstanceID))
	if err != nil || instanceID == uuid.Nil {
		writeErr(w, http.StatusBadRequest, "manage_instance_id must be a UUID")
		return
	}
	if strings.TrimSpace(req.LicenseKey) == "" {
		writeErr(w, http.StatusBadRequest, "license_key required")
		return
	}
	if strings.TrimSpace(req.PublicKeyPEM) == "" {
		writeErr(w, http.StatusBadRequest, "public_key_pem required")
		return
	}

	// 1. Licence gate. A hard error (network/sig) returns 502 because the
	//    caller can't fix the License Server. A parsed response missing
	//    features.manage is 403 — the caller needs a different licence.
	if h.LicenseClient == nil {
		writeErr(w, http.StatusInternalServerError, "license validator not configured")
		return
	}
	features, tenantID, err := h.LicenseClient.Validate(r.Context(), req.LicenseKey)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "license validation failed: "+err.Error())
		return
	}
	if !features.Manage {
		writeErr(w, http.StatusForbidden, "license does not grant manage feature")
		return
	}

	// 2. Parse the caller-provided public key.
	pub, err := parsePublicKeyPEM(req.PublicKeyPEM)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid public_key_pem: "+err.Error())
		return
	}

	// 3. Load the engine CA cert (for the outgoing bundle) and sign the leaf.
	caCertPEM, err := h.CA.LoadCACert(r.Context())
	if err != nil {
		if errors.Is(err, ErrCANotBootstrapped) {
			writeErr(w, http.StatusConflict, "engine CA not bootstrapped for org")
			return
		}
		writeErr(w, http.StatusInternalServerError, "load engine CA: "+err.Error())
		return
	}

	// 4. Sign the leaf. CN binds the licence hash + instance ID so the
	//    mTLS middleware can surface attribution in logs even without a
	//    DB lookup. 12 hex chars of sha256(licenseKey) is enough to
	//    distinguish licences without leaking the raw key in certs.
	licHash := sha256.Sum256([]byte(req.LicenseKey))
	licHashShort := hex.EncodeToString(licHash[:])[:12]
	cn := fmt.Sprintf("manage:%s:%s", licHashShort, instanceID.String())

	leafPEM, err := h.CA.SignLeaf(r.Context(), cn, manageCertValidity, pub)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "sign leaf: "+err.Error())
		return
	}

	// 5. Parse the leaf back to extract its serial — we key the enrolment
	//    row on serial (hex, lowercase) because that's what the mTLS
	//    middleware has cheap access to on every request.
	leafBlock, _ := pem.Decode(leafPEM)
	if leafBlock == nil {
		writeErr(w, http.StatusInternalServerError, "signed leaf failed to decode")
		return
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "signed leaf failed to parse: "+err.Error())
		return
	}
	// Serial.Text(16) matches what x509 emits for leaf.SerialNumber.Text(16)
	// in the mTLS middleware — keep the encoding symmetric on both sides.
	certSerial := leaf.SerialNumber.Text(16)

	// 6. Persist the enrolment BEFORE returning the bundle. If the DB
	//    insert fails, the caller retries with a new instance ID; we
	//    leak a signed cert that nobody can use (not in the DB → mTLS
	//    401). Preferable to the alternative (return a bundle that
	//    Manage trusts but Report can't validate).
	mi := ManageInstance{
		ID:                instanceID,
		LicenseKeyHash:    licHashShort,
		CertSerial:        certSerial,
		TenantAttribution: tenantID,
	}
	if err := h.ManageStore.Create(r.Context(), mi); err != nil {
		writeErr(w, http.StatusInternalServerError, "persist enrolment: "+err.Error())
		return
	}

	bundle, err := BuildBundle(BundleInputs{
		ManageInstanceID: instanceID,
		ReportURL:        h.ReportPublicURL,
		TenantID:         tenantID,
		ClientCertPEM:    leafPEM,
		CACertPEM:        caCertPEM,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "build bundle: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/x-gzip")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="manage-enrol-%s.tar.gz"`, instanceID.String()))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bundle)
}

// parsePublicKeyPEM decodes the first PEM block and returns the parsed
// public key. Accepts a PKIX-wrapped key (the output of
// x509.MarshalPKIXPublicKey → pem.Encode with Type: "PUBLIC KEY"), which
// is what Manage produces.
func parsePublicKeyPEM(s string) (any, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM type %q (want PUBLIC KEY)", block.Type)
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
