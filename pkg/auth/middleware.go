/*
pkg/auth/middleware.go
*/

package auth

import "net/http"

// Middleware d'authentification
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Accès refusé : Token manquant", http.StatusUnauthorized)
			return
		}

		// Supprimer le préfixe "Bearer " s'il est présent
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		// Vérifier le token
		err := verifyToken(tokenString)
		if err != nil {
			http.Error(w, "Accès refusé : Token invalide", http.StatusUnauthorized)
			return
		}

		// Si le token est valide, continuer avec la requête
		next.ServeHTTP(w, r)
	})
}
