package internal

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuth(t *testing.T) {
	id := "102717@glr.nl"
	password := "HEllo@3948"

	t.Run("signup", func(t *testing.T) {
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)

		writer.WriteField("school_email", id)
		writer.WriteField("name", "Leon van Snoeptomaat")
		writer.WriteField("password", password)
		writer.WriteField("role", "fotograaf")
		writer.Close()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/signup", &buf)
		r.Header.Set("Content-Type", writer.FormDataContentType())

		start := time.Now()
		MOCK_SERVER.Signup(w, r)
		fmt.Println("Signup:", time.Since(start))

		if w.Code != http.StatusSeeOther {
			t.Error("failed to redirect user")
		}

		var exists bool
		err := MOCK_SERVER.database.QueryRow(t.Context(), "SELECT EXISTS(SELECT id FROM app_users WHERE school_email = $1)", id).Scan(&exists)
		if err != nil {
			t.Error(err)
		}

		if !exists {
			t.Error("faield to add user to db")
		}
	})

	t.Run("login", func(t *testing.T) {
		writer := url.Values{}
		writer.Set("school_email", id)
		writer.Set("password", password)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(writer.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		start := time.Now()
		MOCK_SERVER.Login(w, r)
		fmt.Println("Login:", time.Since(start))

		if w.Code != http.StatusSeeOther {
			t.Fatalf("failed to redirect user: %d - %v", w.Code, w.Body.String())
		}

	})

}
