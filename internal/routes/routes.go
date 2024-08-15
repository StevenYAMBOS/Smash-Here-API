// internal/routes/routes.go

package routes

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/StevenYAMBOS/Smash-Here-API/api/database"
	"github.com/StevenYAMBOS/Smash-Here-API/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"github.com/StevenYAMBOS/Smash-Here-API/api/jwt"
	"github.com/joho/godotenv"
)

// ==================== Fonctions générales  ====================

// Hacher le mot de passe
func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
			log.Panic("Erreur lors du cryptage du mot de passe [HashPassword] : ", err)
	}

	return string(bytes)
}

// ==================== ROUTEUR  ====================

func Router() http.Handler {
	// Variables d'environnement
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Erreur lors du chargement des variables d'environnement: %s", err)
	}

	router := http.NewServeMux()
	router.Handle("/auth/", AuthRouter())
	router.Handle("/user/", UserRouter())

	router.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// fmt.Fprintf(w, "Bienvenue sur Smash Here")
		fmt.Println("Bienvenue sur Smash Here")
	}))

	return router
}

// ---------- AUTHENTIFICATION  ----------

// Routeur
func AuthRouter() http.Handler {
	authRouter := http.NewServeMux()

	authRouter.HandleFunc("/register", RegisterRoute)
	authRouter.HandleFunc("/login", LoginRoute)

	return http.StripPrefix("/auth", authRouter)
}

// S'inscrire
func RegisterRoute(w http.ResponseWriter, r *http.Request) {
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

	if user.Email == nil || user.Password == nil {
		http.Error(w, "l'email et mot de passe sont requis", http.StatusBadRequest)
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

	collection := database.Client.Database("smash_here_db").Collection("user", )
	_, err = collection.InsertOne(r.Context(), user)
	if err != nil {
		http.Error(w, fmt.Sprintf("Erreur lors de la création du compte : %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, "Utilisateur créé avec succès")
	fmt.Println("Utilisateur créé avec succès : ", user)
}

// Se connecter
func LoginRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Erreur de décodage des données", http.StatusBadRequest)
		return
	}

	collection := database.GetCollection("user")

	var user models.User
	err = collection.FindOne(r.Context(), bson.M{"email": creds.Email}).Decode(&user)
	if err != nil {
		http.Error(w, "Email ou mot de passe incorrect", http.StatusUnauthorized)
		return
	}

	// Comparer les mots de passe
	err = bcrypt.CompareHashAndPassword([]byte(*user.Password), []byte(creds.Password))
	if err != nil {
		http.Error(w, "Email ou mot de passe incorrect", http.StatusUnauthorized)
		return
	}

	// Générer un token JWT
	tokenString, err := token.CreateToken(*user.Email)
	if err != nil {
		http.Error(w, "Erreur lors de la génération du token", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"token": "%s"}`, tokenString)
}

// ---------- UTILISATEUR  ----------

func UserRouter() http.Handler {
	userRouter := http.NewServeMux()

	userRouter.Handle("/home", token.ProtectedHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Bienvenue sur la page d'accueil de l'utilisateur !")
	})))


	return http.StripPrefix("/user", userRouter)
}
