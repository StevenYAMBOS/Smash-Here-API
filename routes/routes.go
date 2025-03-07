package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/StevenYAMBOS/Smash-Here-API/database"
	"github.com/StevenYAMBOS/Smash-Here-API/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

/* ==================== Initialisations ==================== */

// var userCollection = database.Client.Database("smashheredb").Collection("user")

// ==================== Fonctions générales  ====================

// Hacher le mot de passe
func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		log.Panic("Erreur lors du cryptage du mot de passe [HashPassword] : ", err)
	}

	return string(bytes)
}

// Vérifier le hash du mot de passe
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Créer le token de connexion
func createToken(email *string) (string, error) {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Erreur lors du chargement des variables d'environnement: %s", err)
	}

	var SECRET_KEY = os.Getenv("SECRET_KEY")
	var secretKey = []byte(SECRET_KEY)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"email": email,
			"exp":   time.Now().Add(time.Hour * 24).Unix(),
		})

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Vérifier le token
func verifyToken(tokenString string) error {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Erreur lors du chargement des variables d'environnement: %s", err)
	}
	var SECRET_KEY = os.Getenv("SECRET_KEY")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return SECRET_KEY, nil
	})

	if err != nil {
		return err
	}

	if !token.Valid {
		return fmt.Errorf("invalid token")
	}

	return nil
}

// Middleware de connexion
func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Missing authorization header")
		return
	}
	tokenString = tokenString[len("Bearer "):]

	err := verifyToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Token invalide")
		return
	}

	fmt.Fprint(w, "Welcome to the the protected area")

}

// ==================== ROUTEUR ====================

func Router() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", home)
	mux.HandleFunc("POST /auth/register", register)
	mux.HandleFunc("POST /auth/login", login)

	return mux
}

// ==================== ROUTES  ====================

// Route principale
func home(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Bienvenue sur Smash Here"))
}

// ---------- AUTHENTIFICATION  ----------

// Inscription
func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Erreur de décodage des données", http.StatusBadRequest)
		return
	}

	// Vérifications de base
	if user.Username == nil || user.Email == nil || user.Password == nil {
		http.Error(w, "Tous les champs sont obligatoires", http.StatusBadRequest)
		return
	}

	if len(*user.Password) < 6 {
		http.Error(w, "Le mot de passe doit contenir au moins 6 caractères", http.StatusBadRequest)
		return
	}

	// Hacher le mot de passe
	hashedPassword := HashPassword(*user.Password)
	user.Password = &hashedPassword

	// Initialiser d'autres champs
	user.ID = primitive.NewObjectID()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	user.LastLogin = time.Now()

	if database.Client == nil {
		http.Error(w, "Erreur interne: Base de données non initialisée", http.StatusInternalServerError)
		return
	}

	collection := database.Client.Database("smashheredb").Collection("user")
	_, err = collection.InsertOne(r.Context(), user)
	if err != nil {
		http.Error(w, fmt.Sprintf("Erreur lors de la création du compte : %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, "Utilisateur créé avec succès")
	fmt.Println("Utilisateur créé avec succès : ", user)
}

var c *context.Context

// Connexion
func login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// Vérifier si la requête est de type POST
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Initialisation du contexte avec un timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user models.User

	// Décodage du corps de la requête
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Données invalides", http.StatusBadRequest)
		fmt.Println("Données invalides :", err)
		return
	}

	// fmt.Printf("Données de la requête utilisateur %v", user)

	// Vérification des champs obligatoires
	if user.Email == nil || user.Password == nil {
		http.Error(w, "Email et mot de passe sont requis", http.StatusBadRequest)
		fmt.Println("Email et mot de passe sont requis :")
		return
	}

	var storedUser models.User
	err := database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": user.Email}).Decode(&storedUser)
	if err != nil {
		http.Error(w, "Email ou mot de passe incorrect", http.StatusUnauthorized)
		fmt.Println("Email ou mot de passe incorrect : ", err)

		return
	}

	// Vérification du mot de passe
	if !CheckPasswordHash(*user.Password, *storedUser.Password) {
		http.Error(w, "Email ou mot de passe incorrect", http.StatusUnauthorized)
		fmt.Println("Email ou mot de passe incorrect : ", err)
		return
	}

	// Génération du token JWT
	tokenString, err := createToken(storedUser.Email)
	if err != nil {
		http.Error(w, "Erreur lors de la génération du token", http.StatusInternalServerError)
		fmt.Println("Erreur lors de la génération du token : ", err)
		return
	}

	// Mise à jour de la date de dernière connexion
	update := bson.M{"$set": bson.M{"lastLogin": time.Now()}}
	_, err = database.Client.Database("smashheredb").Collection("user").UpdateOne(ctx, bson.M{"email": storedUser.Email}, update)
	if err != nil {
		fmt.Println("Erreur lors de la mise à jour de lastLogin :", err)
	}

	w.WriteHeader(http.StatusOK)
	fmt.Println("Connexion établit : ", user)

	// Envoi du token au client
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}
