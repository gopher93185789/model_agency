package internal

import "net/http"

func (s *ServerContext) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionid, ok := s.validateSession(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		r.Header.Set(middlewareToken, sessionid)
		next.ServeHTTP(w, r)
	}
}
