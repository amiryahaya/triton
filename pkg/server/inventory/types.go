// Package inventory is the Onboarding Inventory bounded context:
// groups of hosts, hosts themselves, and key-value tags attached
// to hosts. All APIs are scoped by org_id enforced at the store layer.
package inventory

import (
	"net"
	"time"

	"github.com/google/uuid"
)

type Group struct {
	ID          uuid.UUID `json:"id"`
	OrgID       uuid.UUID `json:"org_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   uuid.UUID `json:"created_by"`
}

type Host struct {
	ID         uuid.UUID  `json:"id"`
	OrgID      uuid.UUID  `json:"org_id"`
	GroupID    uuid.UUID  `json:"group_id"`
	Hostname   string     `json:"hostname,omitempty"`
	Address    net.IP     `json:"address,omitempty"`
	OS         string     `json:"os,omitempty"`
	Mode       string     `json:"mode"`
	EngineID   *uuid.UUID `json:"engine_id,omitempty"`
	LastScanID *uuid.UUID `json:"last_scan_id,omitempty"`
	LastSeen   *time.Time `json:"last_seen,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	Tags       []Tag      `json:"tags,omitempty"`
}

type Tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
