//go:build integration

package credentials_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/credentials"
)

func testStore(t *testing.T) *credentials.PostgresStore {
	t.Helper()
	pool := testPool(t)
	return credentials.NewPostgresStore(pool)
}

func TestPostgresStore_CreateAndList(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tenantID := uuid.New()
	credID := uuid.New()
	vaultPath := "secret/data/triton/" + tenantID.String() + "/credentials/" + credID.String()
	cred := credentials.Credential{
		ID:        credID,
		TenantID:  tenantID,
		Name:      "prod-ssh",
		AuthType:  credentials.AuthTypeSSHKey,
		VaultPath: vaultPath,
	}
	created, err := s.Create(ctx, cred)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID != credID {
		t.Errorf("id: got %v want %v", created.ID, credID)
	}

	list, err := s.List(ctx, tenantID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].ID != credID {
		t.Errorf("List: got %d items, want 1 with id %v", len(list), credID)
	}
}

func TestPostgresStore_NameConflict(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tenantID := uuid.New()
	cred := credentials.Credential{
		ID: uuid.New(), TenantID: tenantID, Name: "dupe",
		AuthType:  credentials.AuthTypeSSHPassword,
		VaultPath: "secret/data/triton/t/c1",
	}
	if _, err := s.Create(ctx, cred); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	cred2 := cred
	cred2.ID = uuid.New()
	cred2.VaultPath = "secret/data/triton/t/c2"
	if _, err := s.Create(ctx, cred2); !errors.Is(err, credentials.ErrConflict) {
		t.Errorf("duplicate name: want ErrConflict, got %v", err)
	}
}

func TestPostgresStore_Get_NotFound(t *testing.T) {
	s := testStore(t)
	if _, err := s.Get(context.Background(), uuid.New()); !errors.Is(err, credentials.ErrCredentialNotFound) {
		t.Errorf("want ErrCredentialNotFound, got %v", err)
	}
}

func TestPostgresStore_Delete(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tenantID := uuid.New()
	cred := credentials.Credential{
		ID: uuid.New(), TenantID: tenantID, Name: "to-delete",
		AuthType:  credentials.AuthTypeSSHKey,
		VaultPath: "secret/data/triton/t/c",
	}
	if _, err := s.Create(ctx, cred); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Delete(ctx, cred.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, cred.ID); !errors.Is(err, credentials.ErrCredentialNotFound) {
		t.Errorf("after delete: want ErrCredentialNotFound, got %v", err)
	}
}

func TestPostgresStore_CountHosts(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tenantID := uuid.New()
	cred := credentials.Credential{
		ID: uuid.New(), TenantID: tenantID, Name: "unused",
		AuthType:  credentials.AuthTypeSSHKey,
		VaultPath: "secret/data/triton/t/c",
	}
	if _, err := s.Create(ctx, cred); err != nil {
		t.Fatalf("Create: %v", err)
	}
	n, err := s.CountHosts(ctx, cred.ID)
	if err != nil {
		t.Fatalf("CountHosts: %v", err)
	}
	if n != 0 {
		t.Errorf("CountHosts: got %d want 0", n)
	}
}
