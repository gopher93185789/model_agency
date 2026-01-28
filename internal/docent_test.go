package internal

import (
	"context"
	"testing"

	"github.com/google/uuid"
	typespkg "github.com/gopher93185789/model_agency/pkg/types"
)

const testUsersQuery = `
WITH u AS (
  INSERT INTO app_users (role, school_email, name, password_hash)
  VALUES
    ('model', 'user1@glr.nl', 'User One',   decode('deadbeef', 'hex')),
    ('model', 'user2@glr.nl', 'User Two',   decode('deadbeef', 'hex')),
    ('model', 'user3@glr.nl', 'User Three', decode('deadbeef', 'hex')),
    ('model', 'user4@glr.nl', 'User Four',  decode('deadbeef', 'hex')),
    ('model', 'user5@glr.nl', 'User Five',  decode('deadbeef', 'hex'))
  RETURNING id
)
INSERT INTO profile (user_id, approved, description)
SELECT id, false, 'Mock user profile'
FROM u;
`

func TestGetUnapporvedUsers(t *testing.T) {
	ctx := t.Context()
	// Clean existing data to avoid duplicates between tests
	_, _ = MOCK_SERVER.database.Exec(ctx, "DELETE FROM app_users")
	_, err := MOCK_SERVER.database.Exec(ctx, testUsersQuery)
	if err != nil {
		t.Fatal(err)
	}

	profiles, err := MOCK_SERVER.GetUsersForDocentPage(ctx, 10, 1)
	if err != nil {
		t.Fatal(err)
	}

	if len(profiles) != 5 {
		t.Error("failed to retunr sufficient amount of users")
	}
}

func TestSetProfilesApprovalStatus(t *testing.T) {
	ctx := context.Background()

	// Clean existing data to avoid duplicates between tests
	_, _ = MOCK_SERVER.database.Exec(ctx, "DELETE FROM app_users")
	_, err := MOCK_SERVER.database.Exec(ctx, testUsersQuery)
	if err != nil {
		t.Fatal(err)
	}

	getID := func(email string) uuid.UUID {
		var id uuid.UUID
		q := `SELECT id FROM app_users WHERE school_email = $1`
		if err := MOCK_SERVER.database.QueryRow(ctx, q, email).Scan(&id); err != nil {
			t.Fatalf("failed to fetch user id for %s: %v", email, err)
		}
		return id
	}

	u1 := getID("user1@glr.nl")
	u2 := getID("user2@glr.nl")
	u3 := getID("user3@glr.nl")

	updates := []typespkg.ApprovalUpdate{
		{UserID: u1, Status: true},
		{UserID: u2, Status: true},
		{UserID: u3, Status: false},
	}

	if err := MOCK_SERVER.SetProfilesApprovalStatus(ctx, updates); err != nil {
		t.Fatalf("update failed: %v", err)
	}

	check := func(id uuid.UUID, want bool) {
		var approved bool
		q := `SELECT approved FROM profile WHERE user_id = $1`
		if err := MOCK_SERVER.database.QueryRow(ctx, q, id).Scan(&approved); err != nil {
			t.Fatalf("failed to fetch approval for %v: %v", id, err)
		}
		if approved != want {
			t.Fatalf("approval mismatch for %v: want %v got %v", id, want, approved)
		}
	}

	check(u1, true)
	check(u2, true)
	check(u3, false)
}

func TestSetProfilesApprovalStatus_AllOrNothing(t *testing.T) {
	ctx := context.Background()

	// Clean existing data to avoid duplicates between tests
	_, _ = MOCK_SERVER.database.Exec(ctx, "DELETE FROM app_users")
	_, err := MOCK_SERVER.database.Exec(ctx, testUsersQuery)
	if err != nil {
		t.Fatal(err)
	}

	var u1 uuid.UUID
	if err := MOCK_SERVER.database.QueryRow(ctx, `SELECT id FROM app_users WHERE school_email = 'user1@glr.nl'`).Scan(&u1); err != nil {
		t.Fatal(err)
	}

	badID := uuid.New()

	updates := []typespkg.ApprovalUpdate{
		{UserID: u1, Status: true},
		{UserID: badID, Status: true},
	}

	if err := MOCK_SERVER.SetProfilesApprovalStatus(ctx, updates); err == nil {
		t.Fatalf("expected error for nonexistent user id, got nil")
	}

	var approved bool
	if err := MOCK_SERVER.database.QueryRow(ctx, `SELECT approved FROM profile WHERE user_id = $1`, u1).Scan(&approved); err != nil {
		t.Fatal(err)
	}
	if approved {
		t.Fatalf("expected u1 approval to remain false after rollback")
	}
}
