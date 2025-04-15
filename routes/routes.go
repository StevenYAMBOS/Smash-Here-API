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

/* ==================== Fonctions générales  ==================== */

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

	SECRET_KEY := os.Getenv("SECRET_KEY")
	if SECRET_KEY == "" {
		return fmt.Errorf("Clé secrète manquante")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(SECRET_KEY), nil
	})

	if err != nil {
		return err
	}

	if !token.Valid {
		return fmt.Errorf("invalid token")
	}

	return nil
}

// Middleware d'authentification
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		next(w, r)
	}
}

// Extraire l'email du token
func extractEmailFromToken(tokenString string) (string, error) {
	SECRET_KEY := os.Getenv("SECRET_KEY")
	if SECRET_KEY == "" {
		return "", fmt.Errorf("Clé secrète introuvable")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(SECRET_KEY), nil
	})

	if err != nil {
		return "", err
	}

	// Vérifier et récupérer les claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if email, exists := claims["email"].(string); exists {
			return email, nil
		}
	}

	return "", fmt.Errorf("Token invalide ou email manquant")
}

/* ==================== ROUTEUR ==================== */

func Router() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", home)
	mux.HandleFunc("POST /auth/register", register)
	mux.HandleFunc("POST /auth/login", login)
	mux.HandleFunc("POST /superadmin/roadmap", AuthMiddleware(createRoadmap))
	mux.HandleFunc("POST /superadmin/roadmap/{id}/games", AuthMiddleware(addRoadmapToGames))
	mux.HandleFunc("POST /superadmin/game", AuthMiddleware(createGame))
	mux.HandleFunc("GET /user/{id}", GetUserByID)

	return mux
}

/* ==================== ROUTES  ==================== */

// Route principale
func home(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Bienvenue sur Smash Here"))
}

/* ---------- AUTHENTIFICATION  ---------- */

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

/* ---------- GAMES  ---------- */

// Créer un jeu
func createGame(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Vérification du token
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Accès refusé : Token manquant", http.StatusUnauthorized)
		return
	}

	// Supprimer le préfixe "Bearer " si nécessaire
	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}

	// Extraire l'email de l'utilisateur depuis le token
	email, err := extractEmailFromToken(tokenString)
	if err != nil {
		http.Error(w, "Accès refusé : Token invalide", http.StatusUnauthorized)
		return
	}

	// Récupérer l'utilisateur en base de données
	var user models.User
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}

	// Vérifier le rôle de l'utilisateur
	if user.Type == nil || (*user.Type == "user") {
		http.Error(w, "Accès refusé : Vous n'avez pas les permissions pour créer un jeu", http.StatusForbidden)
		return
	}

	// Décoder la roadmap reçue en JSON
	var game models.Game
	err = json.NewDecoder(r.Body).Decode(&game)
	if err != nil {
		http.Error(w, "Format de données invalide", http.StatusBadRequest)
		return
	}

	// Validation des champs obligatoires
	if game.Title == nil || game.Description == nil || game.Subtitle == nil || game.Cover == nil {
		http.Error(w, "Le titre, sous-titre, description et la photo de couverture sont obligatoires", http.StatusBadRequest)
		return
	}

	// Initialisation des champs du jeu
	game.ID = primitive.NewObjectID()
	game.CreatedBy = user.ID
	game.UpdatedBy = user.ID
	game.CreatedAt = time.Now()
	game.UpdatedAt = time.Now()
	game.Published = new(bool) // Par défaut non publié
	game.ViewsPerDay = new(int)
	game.ViewsPerWeek = new(int)
	game.ViewsPerMonth = new(int)
	game.TotalViews = new(int)

	// Insérer la "game" en base de données
	collection := database.Client.Database("smashheredb").Collection("game")
	_, err = collection.InsertOne(ctx, game)
	if err != nil {
		http.Error(w, "Erreur lors de l'ajout du jeu", http.StatusInternalServerError)
		return
	}

	// Réponse de succès
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Jeu créé avec succès"})
}

/* ---------- ROADMAPS  ---------- */

// Créer une roadmap
func createRoadmap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Vérification du token
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Accès refusé : Token manquant", http.StatusUnauthorized)
		return
	}

	// Supprimer le préfixe "Bearer " si nécessaire
	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}

	// Extraire l'email de l'utilisateur depuis le token
	email, err := extractEmailFromToken(tokenString)
	if err != nil {
		http.Error(w, "Accès refusé : Token invalide", http.StatusUnauthorized)
		return
	}

	// Récupérer l'utilisateur en base de données
	var user models.User
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}

	// Vérifier le rôle de l'utilisateur
	if user.Type == nil || (*user.Type == "user") {
		http.Error(w, "Accès refusé : Vous n'avez pas les permissions pour créer une roadmap", http.StatusForbidden)
		return
	}

	// Décoder la roadmap reçue en JSON
	var roadmap models.Roadmap
	err = json.NewDecoder(r.Body).Decode(&roadmap)
	if err != nil {
		http.Error(w, "Format de données invalide", http.StatusBadRequest)
		return
	}

	// Validation des champs obligatoires
	if roadmap.Title == nil || roadmap.Description == nil {
		http.Error(w, "Le titre et la description sont obligatoires", http.StatusBadRequest)
		return
	}

	// Initialisation des champs de la roadmap
	roadmap.ID = primitive.NewObjectID()
	roadmap.CreatedBy = user.ID
	roadmap.UpdatedBy = user.ID
	roadmap.CreatedAt = time.Now()
	roadmap.UpdatedAt = time.Now()
	roadmap.Published = new(bool)
	roadmap.Premium = new(bool)
	roadmap.ViewsPerDay = new(int)
	roadmap.ViewsPerWeek = new(int)
	roadmap.ViewsPerMonth = new(int)
	roadmap.TotalViews = new(int)

	// Insérer la roadmap en base de données
	collection := database.Client.Database("smashheredb").Collection("roadmap")
	_, err = collection.InsertOne(ctx, roadmap)
	if err != nil {
		http.Error(w, "Erreur lors de l'ajout de la roadmap", http.StatusInternalServerError)
		return
	}

	// Réponse de succès
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Roadmap créée avec succès"})
}

// Ajouter une roadmap à une liste de jeux
func addRoadmapToGames(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Vérification du token
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Accès refusé : Token manquant", http.StatusUnauthorized)
		return
	}

	// Supprimer le préfixe "Bearer " si nécessaire
	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}

	// Extraire l'email de l'utilisateur depuis le token
	email, err := extractEmailFromToken(tokenString)
	if err != nil {
		http.Error(w, "Accès refusé : Token invalide", http.StatusUnauthorized)
		return
	}

	// Récupérer l'utilisateur en base de données
	var user models.User
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}

	// Vérifier le rôle de l'utilisateur
	if user.Type == nil || (*user.Type == "user") {
		http.Error(w, "Accès refusé : Vous n'avez pas les permissions pour créer une roadmap", http.StatusForbidden)
		return
	}

	// Récupération de l'ID de la roadmap dans l'URL
	roadmapIDStr := r.URL.Query().Get("id")
	roadmapID, err := primitive.ObjectIDFromHex(roadmapIDStr)
	if err != nil {
		http.Error(w, "ID de roadmap invalide", http.StatusBadRequest)
		return
	}

	// Récupérer les jeux depuis le body
	var payload struct {
		GameIDs []string `json:"Games"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Format du body invalide", http.StatusBadRequest)
		return
	}

	// Conversion en ObjectID
	var gameObjectIDs []primitive.ObjectID
	for _, idStr := range payload.GameIDs {
		gameID, err := primitive.ObjectIDFromHex(idStr)
		if err != nil {
			http.Error(w, fmt.Sprintf("ID de jeu invalide : %s", idStr), http.StatusBadRequest)
			return
		}
		gameObjectIDs = append(gameObjectIDs, gameID)
	}

	// Mise à jour de la roadmap
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	_, err = roadmapCollection.UpdateOne(ctx, bson.M{"_id": roadmapID}, bson.M{
		"$set": bson.M{
			"Games":     gameObjectIDs,
			"UpdatedAt": time.Now(),
			"UpdatedBy": user.ID,
		},
	})
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour de la roadmap", http.StatusInternalServerError)
		return
	}

	gameCollection := database.Client.Database("smashheredb").Collection("game")
	for _, gameID := range gameObjectIDs {
		_, err := gameCollection.UpdateOne(ctx, bson.M{"_id": gameID}, bson.M{
			"$addToSet": bson.M{
				"Roadmaps": roadmapID,
			},
			"$set": bson.M{
				"UpdatedAt": time.Now(),
				"UpdatedBy": user.ID,
			},
		})
		if err != nil {
			http.Error(w, fmt.Sprintf("Erreur lors de la mise à jour du jeu : %s", gameID.Hex()), http.StatusInternalServerError)
			return
		}
	}

	json.NewEncoder(w).Encode(map[string]any{
		"message":      "Roadmap et jeux mis à jour avec succès",
		"roadmap_id":   roadmapID.Hex(),
		"linked_games": payload.GameIDs,
		"updated_by":   user.Email,
		"updated_at":   time.Now(),
	})
}

func GetUserByID(w http.ResponseWriter, r *http.Request) {

	id, err := primitive.ObjectIDFromHex(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	collection := database.Client.Database("smashheredb").Collection("user")
	var user models.User
	if err := collection.FindOne(context.Background(), bson.M{"_id": id}).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(user)
}
