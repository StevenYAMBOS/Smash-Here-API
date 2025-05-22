/*
internal/user/interfaces/handler.go
*/

package interfaces

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/StevenYAMBOS/Smash-Here-API/internal/user/service"
	"github.com/StevenYAMBOS/Smash-Here-API/pkg/auth"
)

var c *context.Context

// instanciation globale (ou via injection)
var userService = service.NewUserService()

// Inscription
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	file, header, err := r.FormFile("profilePicture")
	if err != nil {
		http.Error(w, "Image manquante ou invalide", http.StatusBadRequest)
		return
	}
	defer file.Close()

	user, err := userService.Register(ctx, username, email, password, file, header)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"message":        "Utilisateur créé avec succès",
		"profilePicture": *user.ProfilePicture,
	})
}

// Connexion
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// Vérifier si la requête est de type POST
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var body struct{ Email, Password string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Données invalides", http.StatusBadRequest)
		return
	}
	token, err := userService.Login(ctx, body.Email, body.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// Récupérer les informations du profil
func GetProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Authentification
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Token manquant", http.StatusUnauthorized)
		return
	}
	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}
	email, err := auth.ExtractEmailFromToken(tokenString)
	if err != nil {
		http.Error(w, "Token invalide", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Récupérer l'utilisateur
	user, err := userService.GetProfile(ctx, email)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(user)
}
