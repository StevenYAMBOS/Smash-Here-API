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
	"github.com/go-chi/chi/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
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

// Récupérer les roadmaps d'un utilisateur
func GetUserRoadmapsHandler(w http.ResponseWriter, r *http.Request) {
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

	roadmaps, err := userService.GetUserRoadmaps(ctx, email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(roadmaps)
}

// Modifier le profil
func UpdateProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Erreur parsing multipart", http.StatusBadRequest)
		return
	}

	// Auth
	token := r.Header.Get("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}
	email, err := auth.ExtractEmailFromToken(token)
	if err != nil {
		http.Error(w, "Token invalide", http.StatusUnauthorized)
		return
	}

	// Extraire champs
	newUsername := r.FormValue("username")
	file, header, _ := r.FormFile("profilePicture")
	if file != nil {
		defer file.Close()
	}

	// Appel service
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	updatedUser, err := userService.UpdateProfile(ctx, email, newUsername, file, header)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedUser)
}

// Récupérer les informations d'un autre utilisateur
func GetUserByIdHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Méthode
	if r.Method != http.MethodGet {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// 2. Authentification
	token := r.Header.Get("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}
	currentEmail, err := auth.ExtractEmailFromToken(token)
	if err != nil {
		http.Error(w, "Token invalide", http.StatusUnauthorized)
		return
	}

	// Récupérer l'ID cible depuis l'URL
	idParam := chi.URLParam(r, "id")
	targetID, err := primitive.ObjectIDFromHex(idParam)
	if err != nil {
		http.Error(w, "ID invalide", http.StatusBadRequest)
		return
	}

	// Appel service
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	user, err := userService.GetUserByID(ctx, currentEmail, targetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}
