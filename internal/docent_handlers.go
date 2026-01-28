package internal

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/gopher93185789/model_agency/pkg/types"
)

// ApproveUserRequest handles approval toggle
type ApproveUserRequest struct {
	UserID   string `json:"user_id"`
	Approved bool   `json:"approved"`
}

// RevokeUserRequest handles user deletion
type RevokeUserRequest struct {
	UserID string `json:"user_id"`
}

// HandleApproveUser toggles user approval status
func (s *ServerContext) HandleApproveUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check if user is docent
	sid := r.Header.Get(middlewareToken)
	if sid == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims, err := s.parseToken(sid)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if types.Role(claims.Role) != types.RoleDocent {
		http.Error(w, "Forbidden: Only docents can approve users", http.StatusForbidden)
		return
	}

	var req ApproveUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Failed to decode request: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		log.Printf("Invalid user ID: %v", err)
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Update approval status
	updates := []types.ApprovalUpdate{
		{UserID: userID, Status: req.Approved},
	}

	if err := s.SetProfilesApprovalStatus(ctx, updates); err != nil {
		log.Printf("Failed to update approval status: %v", err)
		http.Error(w, "Failed to update status", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"user_id":  req.UserID,
		"approved": req.Approved,
	})
}

// HandleRevokeUser deletes a user account
func (s *ServerContext) HandleRevokeUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check if user is docent
	sid := r.Header.Get(middlewareToken)
	if sid == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims, err := s.parseToken(sid)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if types.Role(claims.Role) != types.RoleDocent {
		http.Error(w, "Forbidden: Only docents can approve users", http.StatusForbidden)
		return
	}

	var req RevokeUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Failed to decode request: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		log.Printf("Invalid user ID: %v", err)
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Delete user
	q := `DELETE FROM app_users WHERE id = $1 AND id IN (SELECT user_id FROM profile WHERE user_id = $1)`
	result, err := s.database.Exec(ctx, q, userID)
	if err != nil {
		log.Printf("Failed to delete user: %v", err)
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	if result.RowsAffected() == 0 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"user_id": req.UserID,
	})
}
