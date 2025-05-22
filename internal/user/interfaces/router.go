/*
internal/user/interfaces/router.go
*/

package interfaces

import (
	"github.com/StevenYAMBOS/Smash-Here-API/pkg/auth"
	"github.com/go-chi/chi/v5"
)

// Routeur utilisateurs
func UserRoutes(r chi.Router) {
	r.Route("/user", func(r chi.Router) {
		r.Use(auth.AuthMiddleware)
		r.Get("/profile", GetProfileHandler)
	})
}

// Routeur dauthentification
func AuthRoutes(r chi.Router) {
	r.Route("/auth", func(r chi.Router) {
		r.Post("/register", RegisterHandler)
		r.Post("/login", LoginHandler)
	})
}
