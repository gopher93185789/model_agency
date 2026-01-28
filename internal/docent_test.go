package internal

import (
	"testing"
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
