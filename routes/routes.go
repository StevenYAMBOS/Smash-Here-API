package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
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

	// Authentification
	mux.HandleFunc("/", home)
	mux.HandleFunc("POST /auth/register", register)
	mux.HandleFunc("POST /auth/login", login)
	// Utilisateur
	mux.HandleFunc("GET /user/roadmaps", AuthMiddleware(getUserRoadmaps))
	mux.HandleFunc("POST /roadmap/{id}/comments", AuthMiddleware(addCommentToRoadmap))
	mux.HandleFunc("PUT /user/bookmarks", AuthMiddleware(addRoadmapToBookmarks))
	mux.HandleFunc("DELETE /user/bookmarks", AuthMiddleware(removeRoadmapToBookmarks))
	// Roadmap
	mux.HandleFunc("GET /roadmap/{id}", getRoadmap)
	mux.HandleFunc("GET /superadmin/roadmaps", AuthMiddleware(getAllRoadmaps))
	mux.HandleFunc("POST /roadmap", AuthMiddleware(createRoadmap))
	mux.HandleFunc("POST /superadmin/roadmap", AuthMiddleware(createSpecialRoadmap))
	mux.HandleFunc("PUT /superadmin/roadmaps/{id}/games", AuthMiddleware(addRoadmapToGames))
	mux.HandleFunc("PUT /roadmap/{id}", AuthMiddleware(updateOneRoadmap))
	mux.HandleFunc("PUT /roadmap/{id}/remove-tags", AuthMiddleware(removeTagsFromRoadmap))
	mux.HandleFunc("DELETE /superadmin/roadmap/{id}", AuthMiddleware(deleteOneRoadmap))
	// Étapes
	mux.HandleFunc("POST /step", AuthMiddleware(createStep))
	mux.HandleFunc("PUT /step/{id}", AuthMiddleware(updateOneStep))
	mux.HandleFunc("PUT /steps/{id}/roadmaps", AuthMiddleware(addStepToRoadmaps))
	mux.HandleFunc("GET /step/{id}", getOneStep)
	mux.HandleFunc("GET /superadmin/steps", AuthMiddleware(getAllSteps))
	mux.HandleFunc("DELETE /step/{id}", AuthMiddleware(deleteOneStep))
	// Contenus
	mux.HandleFunc("POST /content", AuthMiddleware(createContent))
	mux.HandleFunc("PUT /content/{id}", AuthMiddleware(updateOneContent))
	mux.HandleFunc("PUT /contents/{id}/steps", AuthMiddleware(addContentToSteps))
	mux.HandleFunc("GET /content/{id}", getOneContent)
	mux.HandleFunc("GET /superadmin/contents", AuthMiddleware(getAllContents))
	mux.HandleFunc("GET /user/contents", AuthMiddleware(getUserContents))
	mux.HandleFunc("DELETE /content/{id}", AuthMiddleware(deleteOneContent))
	// Tags
	mux.HandleFunc("POST /superadmin/tag", AuthMiddleware(createTag))
	mux.HandleFunc("GET /tags", AuthMiddleware(getAllTags))
	mux.HandleFunc("PUT /superadmin/tag/{id}", AuthMiddleware(updateOneTag))
	mux.HandleFunc("PUT /superadmin/tags/{id}/roadmaps", AuthMiddleware(addTagToRoadmaps))
	mux.HandleFunc("DELETE /superadmin/tag/{id}", AuthMiddleware(deleteOneTag))
	// Jeux
	mux.HandleFunc("POST /superadmin/game", AuthMiddleware(createGame))
	mux.HandleFunc("GET /game/{id}/roadmaps", AuthMiddleware(getRoadmapsFromGame))

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

/* ---------- UTILISATEUR  ---------- */

// Ajouter une roadmap aux favoris
func addRoadmapToBookmarks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
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
		http.Error(w, "Token invalide", http.StatusUnauthorized)
		return
	}

	// Récupérer l'utilisateur en base de données
	var userCollection = database.Client.Database("smashheredb").Collection("user")
	var user models.User
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = userCollection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}

	// Vérifier le rôle de l'utilisateur
	if user.ID.IsZero() {
		http.Error(w, "Utilisateur invalide", http.StatusForbidden)
		return
	}

	// Récupérer la roadmap depuis le body
	var payload struct {
		RoadmapID string `json:"roadmapId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Format du body invalide", http.StatusBadRequest)
		return
	}

	// Transformer l'id en `ObjectId`
	roadmapID, err := primitive.ObjectIDFromHex(payload.RoadmapID)
	if err != nil {
		http.Error(w, "ID invalide", http.StatusBadRequest)
		return
	}

	// Vérifier que la roadmap existe
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")

	var roadmap models.Roadmap
	err = roadmapCollection.FindOne(ctx, bson.M{"_id": roadmapID}).Decode(&roadmap)
	if err != nil {
		http.Error(w, "La roadmap spécifiée n'existe pas", http.StatusNotFound)
		return
	}

	// Mise à jour de l'utilisateur
	result, err := userCollection.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{
		"$addToSet": bson.M{
			"Bookmarks": roadmapID,
		},
	})
	if err != nil {
		http.Error(w, "Erreur lors de l'ajout de la roadmap aux favoris", http.StatusInternalServerError)
		return
	}
	if result.MatchedCount == 0 {
		log.Println(roadmapID)
		http.Error(w, "Aucune roadmap ajoutée", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"message": "Roadmap ajoutée aux favoris",
	})
}

// Retirer une roadmap des favoris
func removeRoadmapToBookmarks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Vérification du token
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Token manquant", http.StatusUnauthorized)
		return
	}
	if strings.HasPrefix(token, "Bearer ") {
		token = token[7:]
	}

	email, err := extractEmailFromToken(token)
	if err != nil {
		http.Error(w, "Token invalide", http.StatusUnauthorized)
		return
	}

	// Récupération de l'utilisateur
	var user models.User
	userCollection := database.Client.Database("smashheredb").Collection("user")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}

	// Vérification du rôle
	if user.ID.IsZero() {
		http.Error(w, "Utilisateur invalide", http.StatusForbidden)
		return
	}

	// Lecture du body
	var payload struct {
		RoadmapID string `json:"roadmapId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Body invalide", http.StatusBadRequest)
		return
	}

	// Transformer l'id en `ObjectId`
	roadmapID, err := primitive.ObjectIDFromHex(payload.RoadmapID)
	if err != nil {
		http.Error(w, "ID invalide", http.StatusBadRequest)
		return

	}

	// Vérification de l'existence de la roadmap
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	var roadmap models.Roadmap
	err = roadmapCollection.FindOne(ctx, bson.M{"_id": roadmapID}).Decode(&roadmap)
	if err != nil {
		http.Error(w, "Roadmap introuvable", http.StatusNotFound)
		return
	}

	result, err := userCollection.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{
		"$pull": bson.M{
			"Bookmarks": roadmapID,
		},
	})
	if err != nil {
		fmt.Println(roadmapID)
		http.Error(w, "Erreur lors de la mise à jour des favoris", http.StatusInternalServerError)
		return
	}

	// Réponse
	json.NewEncoder(w).Encode(map[string]any{
		"message":  "Roadmap retirée des favoris",
		"modified": result.ModifiedCount,
	})
}

// Récupérer les roadmaps d'un utilisateur
func getUserRoadmaps(w http.ResponseWriter, r *http.Request) {
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
	email, err := extractEmailFromToken(tokenString)
	if err != nil {
		http.Error(w, "Token invalide", http.StatusUnauthorized)
		return
	}

	// Récupérer l'utilisateur
	var user models.User
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}

	// Récupérer les roadmaps de l'utilisateur depuis le champ `RoadmapsCreated`
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	cursor, err := roadmapCollection.Find(ctx, bson.M{"_id": bson.M{"$in": user.RoadmapsCreated}})
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des roadmaps", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var roadmaps []models.Roadmap
	if err := cursor.All(ctx, &roadmaps); err != nil {
		http.Error(w, "Erreur lors du parsing des données", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(roadmaps)
}

// Ajouter un commentaire à une roadmap
func addCommentToRoadmap(w http.ResponseWriter, r *http.Request) {
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
	var userCollection = database.Client.Database("smashheredb").Collection("user")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}

	// Vérifier le rôle de l'utilisateur
	if user.ID.IsZero() {
		http.Error(w, "Utilisateur invalide", http.StatusForbidden)
		return
	}

	// Extraire l’ID de roadmap depuis l’URL
	pathParts := strings.Split(r.URL.Path, "/")

	if len(pathParts) < 4 || pathParts[1] != "roadmap" || pathParts[3] != "comments" {
		http.Error(w, "URL invalide", http.StatusBadRequest)
		return
	}

	roadmapIDStr := pathParts[2]

	roadmapID, err := primitive.ObjectIDFromHex(roadmapIDStr)
	if err != nil {
		http.Error(w, "ID de roadmap invalide", http.StatusBadRequest)
		return
	}

	// Vérifier que la roadmap existe
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	var roadmap models.Roadmap
	err = roadmapCollection.FindOne(ctx, bson.M{"_id": roadmapID}).Decode(&roadmap)
	if err != nil {
		http.Error(w, "La roadmap spécifiée n'existe pas", http.StatusNotFound)
		return
	}

	// Décoder le commentaire reçu en JSON
	var comment models.Comment
	err = json.NewDecoder(r.Body).Decode(&comment)
	if err != nil {
		http.Error(w, "Format de données invalide", http.StatusBadRequest)
		return
	}

	// Validation des champs obligatoires
	if comment.Message == nil {
		http.Error(w, "Le message est requis", http.StatusBadRequest)
		return
	}

	// Initialisation des champs du jeu
	comment.Roadmap = roadmapID
	comment.User = user.ID
	comment.ID = primitive.NewObjectID()
	comment.CreatedBy = user.ID
	comment.UpdatedBy = user.ID
	comment.CreatedAt = time.Now()
	comment.UpdatedAt = time.Now()

	// Collection commentaire (`comment`)
	commentCollection := database.Client.Database("smashheredb").Collection("comment")
	_, err = commentCollection.InsertOne(ctx, comment)
	if err != nil {
		http.Error(w, "Erreur lors de l'ajout du commentaire", http.StatusInternalServerError)
		return
	}

	// Collection Roadmap (`roadmap`)
	result, err := roadmapCollection.UpdateOne(ctx, bson.M{"_id": roadmapID}, bson.M{
		"$addToSet": bson.M{
			"Comments": comment.ID,
		},
	})
	if err != nil {
		http.Error(w, "Erreur lors de l'ajout du commentaire dans la roadmap", http.StatusInternalServerError)
		return
	}
	if result.MatchedCount == 0 {
		http.Error(w, "Aucun commentaire ajoutée dans la roadmap", http.StatusNotFound)
		return
	}

	// Collection Utilisateur (`user`)
	resultForUser, err := userCollection.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{
		"$addToSet": bson.M{
			"Comments": comment.ID,
		},
	})
	if err != nil {
		http.Error(w, "Erreur lors de l'ajout du commentaire dans le document de l'utilisateur", http.StatusInternalServerError)
		return
	}
	if resultForUser.MatchedCount == 0 {
		http.Error(w, "Aucun commentaire ajoutée dans le document de l'utilisateur", http.StatusNotFound)
		return
	}

	// Réponse de succès
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"message": "Commentaire créé avec succès",
		"comment": comment,
	})
}

/* ---------- JEUX  ---------- */

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

	// Décoder le jeu reçu en JSON
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
	game.Published = new(bool)
	game.ViewsPerDay = new(int)
	game.ViewsPerWeek = new(int)
	game.ViewsPerMonth = new(int)
	game.TotalViews = new(int)

	// Insérer le jeu en base de données
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

// Récupérer la liste des roadmaps d'un jeu
func getRoadmapsFromGame(w http.ResponseWriter, r *http.Request) {
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
	email, err := extractEmailFromToken(tokenString)
	if err != nil {
		http.Error(w, "Token invalide", http.StatusUnauthorized)
		return
	}

	// Récupérer l'utilisateur
	var user models.User
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}

	// Extraire l’ID du jeu depuis l’URL
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 4 || pathParts[1] != "game" {
		log.Println(pathParts)
		http.Error(w, "URL invalide", http.StatusBadRequest)
		return
	}
	gameIDStr := pathParts[2]
	gameID, err := primitive.ObjectIDFromHex(gameIDStr)
	if err != nil {
		http.Error(w, "ID du jeu invalide", http.StatusBadRequest)
		return
	}

	// Vérifier que le jeu existe
	gameCollection := database.Client.Database("smashheredb").Collection("game")
	var game models.Game
	err = gameCollection.FindOne(ctx, bson.M{"_id": gameID}).Decode(&game)
	if err != nil {
		http.Error(w, "Le jeu spécifié n'existe pas", http.StatusNotFound)
		return
	}

	// Récupérer les roadmaps
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	cursor, err := roadmapCollection.Find(ctx, bson.M{"_id": bson.M{"$in": game.Roadmaps}})
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des roadmaps", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var roadmaps []models.Roadmap
	if err := cursor.All(ctx, &roadmaps); err != nil {
		http.Error(w, "Erreur lors du parsing des données", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(roadmaps)
}

/* ---------- ROADMAPS  ---------- */

// Créer une roadmap (Superadmin uniquement)
func createSpecialRoadmap(w http.ResponseWriter, r *http.Request) {
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
	if user.Type == nil || (*user.Type == "user") || (*user.Type == "coach") {
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

	// Ajouter la roadmap à l'utilisateur
	userCollection := database.Client.Database("smashheredb").Collection("user")
	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{
		"$addToSet": bson.M{
			"RoadmapsCreated": roadmap.ID,
		},
	})
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour de l'utilisateur", http.StatusInternalServerError)
		return
	}

	// Réponse de succès
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Roadmap créée avec succès"})
}

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

	// Ajouter la roadmap à l'utilisateur
	userCollection := database.Client.Database("smashheredb").Collection("user")
	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{
		"$addToSet": bson.M{
			"RoadmapsCreated": roadmap.ID,
		},
	})
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour de l'utilisateur", http.StatusInternalServerError)
		return
	}

	// Réponse de succès
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Roadmap créée avec succès"})
}

// Ajouter une roadmap à une liste de jeux
func addRoadmapToGames(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
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

	// Extraire l’ID de roadmap depuis l’URL
	pathParts := strings.Split(r.URL.Path, "/")

	if len(pathParts) < 5 || pathParts[4] != "games" {
		http.Error(w, "URL invalide", http.StatusBadRequest)
		return
	}

	roadmapIDStr := pathParts[3]

	roadmapID, err := primitive.ObjectIDFromHex(roadmapIDStr)
	if err != nil {
		http.Error(w, "ID de roadmap invalide", http.StatusBadRequest)
		return
	}

	// Vérifier que la roadmap existe
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	var roadmap models.Roadmap
	err = roadmapCollection.FindOne(ctx, bson.M{"_id": roadmapID}).Decode(&roadmap)
	if err != nil {
		http.Error(w, "La roadmap spécifiée n'existe pas", http.StatusNotFound)
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
	result, err := roadmapCollection.UpdateOne(ctx, bson.M{"_id": roadmapID}, bson.M{
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
	if result.MatchedCount == 0 {
		http.Error(w, "Aucune roadmap mise à jour", http.StatusNotFound)
		return
	}

	gameCollection := database.Client.Database("smashheredb").Collection("game")
	for _, gameID := range gameObjectIDs {
		res, err := gameCollection.UpdateOne(ctx, bson.M{"_id": gameID}, bson.M{
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
		if res.MatchedCount == 0 {
			log.Printf("Aucun jeu trouvé pour l'ID %s\n", gameID.Hex())
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

// Récupérer une roadmap
func getRoadmap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	roadmapIdFromPath := strings.TrimPrefix(r.URL.Path, "/roadmap/")
	roadmapID, err := primitive.ObjectIDFromHex(roadmapIdFromPath)
	if err != nil {
		http.Error(w, "ID de la roadmap invalide", http.StatusBadRequest)
		return
	}

	// Vérifier que la roadmap existe
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	var roadmap models.Roadmap
	err = roadmapCollection.FindOne(ctx, bson.M{"_id": roadmapID}).Decode(&roadmap)
	if err != nil {
		http.Error(w, "La roadmap spécifiée n'existe pas", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(roadmap)
}

// Récupérer toutes les roadmaps
func getAllRoadmaps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
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
	if user.Type == nil || (*user.Type == "user") || (*user.Type == "coach") {
		http.Error(w, "Accès refusé : Vous n'avez pas les permissions pour récupérer toutes les roadmaps", http.StatusForbidden)
		return
	}

	// Vérifier que la roadmap existe
	var roadmaps []models.Roadmap
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	cursor, err := roadmapCollection.Find(context.Background(), bson.D{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var roadmap models.Roadmap
		if err := cursor.Decode(&roadmap); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		roadmaps = append(roadmaps, roadmap)
	}

	json.NewEncoder(w).Encode(roadmaps)
}

// Supprimer une roadmap
func deleteOneRoadmap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Auth
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Token manquant", http.StatusUnauthorized)
		return
	}
	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}
	email, err := extractEmailFromToken(tokenString)
	if err != nil {
		http.Error(w, "Token invalide", http.StatusUnauthorized)
		return
	}

	// Récupérer l'utilisateur
	var user models.User
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}
	if user.Type == nil || (*user.Type == "user") {
		http.Error(w, "Accès refusé", http.StatusForbidden)
		return
	}

	// ID roadmap
	roadmapIdStr := strings.TrimPrefix(r.URL.Path, "/superadmin/roadmap/")
	roadmapID, err := primitive.ObjectIDFromHex(roadmapIdStr)
	if err != nil {
		http.Error(w, "ID de roadmap invalide", http.StatusBadRequest)
		return
	}

	// Suppression de la roadmap
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	result, err := roadmapCollection.DeleteOne(ctx, bson.M{"_id": roadmapID})
	if err != nil {
		http.Error(w, "Erreur lors de la suppression de la roadmap", http.StatusInternalServerError)
		return
	}

	// Mise à jour des jeux
	gameCollection := database.Client.Database("smashheredb").Collection("game")
	_, err = gameCollection.UpdateMany(ctx,
		bson.M{"Roadmaps": roadmapID},
		bson.M{"$pull": bson.M{"Roadmaps": roadmapID}},
	)
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour des jeux", http.StatusInternalServerError)
		return
	}

	// Mise à jour des utilisateurs
	userCollection := database.Client.Database("smashheredb").Collection("user")
	_, err = userCollection.UpdateMany(ctx,
		bson.M{"$or": []bson.M{
			{"Bookmarks": roadmapID},
			{"RoadmapsCreated": roadmapID},
			{"RoadmapsStarted": roadmapID},
		}},
		bson.M{"$pull": bson.M{
			"Bookmarks":       roadmapID,
			"RoadmapsCreated": roadmapID,
			"RoadmapsStarted": roadmapID,
		}},
	)
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour des utilisateurs", http.StatusInternalServerError)
		return
	}

	// Mise à jour des étapes
	stepCollection := database.Client.Database("smashheredb").Collection("step")
	_, err = stepCollection.UpdateMany(ctx,
		bson.M{"Roadmaps": roadmapID},
		bson.M{"$pull": bson.M{"Roadmaps": roadmapID}},
	)
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour des étapes", http.StatusInternalServerError)
		return
	}

	// Suppression des progressions
	progressionCollection := database.Client.Database("smashheredb").Collection("progression")
	_, err = progressionCollection.DeleteMany(ctx, bson.M{"Roadmap": roadmapID})
	if err != nil {
		http.Error(w, "Erreur lors de la suppression des progressions", http.StatusInternalServerError)
		return
	}

	// Réponse OK
	json.NewEncoder(w).Encode(map[string]any{
		"message":       "Roadmap supprimée avec succès",
		"deleted_count": result.DeletedCount,
	})
}

// Modifier une roadmap
func updateOneRoadmap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
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
	email, err := extractEmailFromToken(tokenString)
	if err != nil {
		http.Error(w, "Token invalide", http.StatusUnauthorized)
		return
	}

	// Récupérer l'utilisateur
	var user models.User
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}
	if user.Type == nil || (*user.Type == "user") {
		http.Error(w, "Accès refusé", http.StatusForbidden)
		return
	}

	// Récupérer l'ID de la roadmap
	roadmapIDStr := strings.TrimPrefix(r.URL.Path, "/roadmap/")
	roadmapID, err := primitive.ObjectIDFromHex(roadmapIDStr)
	if err != nil {
		http.Error(w, "ID de roadmap invalide", http.StatusBadRequest)
		return
	}

	// Body à mettre à jour
	var updatedRoadmap models.Roadmap
	if err := json.NewDecoder(r.Body).Decode(&updatedRoadmap); err != nil {
		http.Error(w, "Corps invalide", http.StatusBadRequest)
		return
	}

	// Construction du $set dynamique
	updateFields := bson.M{}
	if updatedRoadmap.Title != nil {
		updateFields["title"] = updatedRoadmap.Title
	}
	if updatedRoadmap.SubTitle != nil {
		updateFields["subTitle"] = updatedRoadmap.SubTitle
	}
	if updatedRoadmap.Description != nil {
		updateFields["description"] = updatedRoadmap.Description
	}
	if updatedRoadmap.Published != nil {
		updateFields["published"] = updatedRoadmap.Published
	}
	if updatedRoadmap.Premium != nil {
		updateFields["premium"] = updatedRoadmap.Premium
	}
	if updatedRoadmap.Tags != nil {
		updateFields["Tags"] = updatedRoadmap.Tags
	}
	// Champs automatiques
	updateFields["UpdatedAt"] = time.Now()
	updateFields["UpdatedBy"] = user.ID

	// Si aucun champ modifié
	if len(updateFields) == 0 {
		http.Error(w, "Aucun champ valide à modifier", http.StatusBadRequest)
		return
	}

	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	filter := bson.M{"_id": roadmapID}
	update := bson.M{"$set": updateFields}
	result, err := roadmapCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour", http.StatusInternalServerError)
		return
	}
	if result.MatchedCount == 0 {
		http.Error(w, "Aucune roadmap trouvée", http.StatusNotFound)
		return
	}

	// Réponse OK
	json.NewEncoder(w).Encode(map[string]any{
		"message":    "Roadmap modifiée avec succès",
		"updated_at": time.Now(),
		"modified":   result.ModifiedCount,
	})
}

// Supprimer plusieurs tags d'une roadmap
func removeTagsFromRoadmap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Vérification du token
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Token manquant", http.StatusUnauthorized)
		return
	}
	if strings.HasPrefix(token, "Bearer ") {
		token = token[7:]
	}

	email, err := extractEmailFromToken(token)
	if err != nil {
		http.Error(w, "Token invalide", http.StatusUnauthorized)
		return
	}

	// Récupération de l'utilisateur
	var user models.User
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}

	// Vérification du rôle
	if user.Type == nil || (*user.Type != "superadmin" && *user.Type != "coach") {
		http.Error(w, "Accès refusé", http.StatusForbidden)
		return
	}

	// Récupération de l'ID de roadmap dans l'URL
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 4 {
		http.Error(w, "URL invalide", http.StatusBadRequest)
		return
	}
	roadmapIDStr := pathParts[2]
	roadmapID, err := primitive.ObjectIDFromHex(roadmapIDStr)
	if err != nil {
		http.Error(w, "ID de roadmap invalide", http.StatusBadRequest)
		return
	}

	// Vérification de l'existence de la roadmap
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	var roadmap models.Roadmap
	err = roadmapCollection.FindOne(ctx, bson.M{"_id": roadmapID}).Decode(&roadmap)
	if err != nil {
		http.Error(w, "Roadmap introuvable", http.StatusNotFound)
		return
	}

	// Lecture du body (liste de tagIDs)
	var payload struct {
		TagIDs []string `json:"Tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Body invalide", http.StatusBadRequest)
		return
	}

	// Conversion en ObjectID
	var tagObjectIDs []primitive.ObjectID
	for _, id := range payload.TagIDs {
		tagID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			http.Error(w, fmt.Sprintf("TagID invalide : %s", id), http.StatusBadRequest)
			return
		}
		tagObjectIDs = append(tagObjectIDs, tagID)
	}

	// Suppression des tags
	update := bson.M{
		"$pull": bson.M{
			"Tags": bson.M{
				"$in": tagObjectIDs,
			},
		},
		"$set": bson.M{
			"UpdatedAt": time.Now(),
			"UpdatedBy": user.ID,
		},
	}
	result, err := roadmapCollection.UpdateOne(ctx, bson.M{"_id": roadmapID}, update)
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour", http.StatusInternalServerError)
		return
	}

	// Réponse
	json.NewEncoder(w).Encode(map[string]any{
		"message":      "Tags supprimés de la roadmap",
		"roadmap_id":   roadmapID.Hex(),
		"tags_removed": payload.TagIDs,
		"updated_by":   user.Email,
		"updated_at":   time.Now(),
		"modified":     result.ModifiedCount,
	})
}

/* ---------- ÉTAPES  ---------- */

// Créer une étape
func createStep(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "Accès refusé : Vous n'avez pas les permissions pour créer une étape", http.StatusForbidden)
		return
	}

	// Décoder l'étape reçue en JSON
	var step models.Step
	err = json.NewDecoder(r.Body).Decode(&step)
	if err != nil {
		http.Error(w, "Format de données invalide", http.StatusBadRequest)
		return
	}

	// Validation des champs obligatoires
	if step.Title == nil || step.Description == nil || step.Subtitle == nil {
		http.Error(w, "Le titre, sous-titre et la description sont obligatoires", http.StatusBadRequest)
		return
	}

	// Initialisation des champs de la step
	step.ID = primitive.NewObjectID()
	step.CreatedBy = user.ID
	step.UpdatedBy = user.ID
	step.CreatedAt = time.Now()
	step.UpdatedAt = time.Now()

	// Insérer la step en base de données
	stepCollection := database.Client.Database("smashheredb").Collection("step")
	_, err = stepCollection.InsertOne(ctx, step)
	if err != nil {
		http.Error(w, "Erreur lors de l'ajout de l'étape", http.StatusInternalServerError)
		return
	}

	// Réponse de succès
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Étape créée avec succès"})
}

// Récupérer une étape
func getOneStep(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stepIdFromPath := strings.TrimPrefix(r.URL.Path, "/step/")
	stepID, err := primitive.ObjectIDFromHex(stepIdFromPath)
	if err != nil {
		http.Error(w, "ID de l'étape invalide", http.StatusBadRequest)
		return
	}

	// Vérifier que l'étape existe
	stepCollection := database.Client.Database("smashheredb").Collection("step")
	var step models.Step
	err = stepCollection.FindOne(ctx, bson.M{"_id": stepID}).Decode(&step)
	if err != nil {
		http.Error(w, "La step spécifiée n'existe pas", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(step)
}

// Récupérer toutes les étapes
func getAllSteps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
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
	if user.Type == nil || (*user.Type == "user") || (*user.Type == "coach") {
		http.Error(w, "Accès refusé : Vous n'avez pas les permissions pour récupérer toutes les étapes", http.StatusForbidden)
		return
	}

	// Vérifier que l'étape existe
	var steps []models.Step
	stepCollection := database.Client.Database("smashheredb").Collection("step")
	cursor, err := stepCollection.Find(context.Background(), bson.D{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var step models.Step
		if err := cursor.Decode(&step); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		steps = append(steps, step)
	}

	json.NewEncoder(w).Encode(steps)
}

// Modifier une étape
func updateOneStep(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
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
	email, err := extractEmailFromToken(tokenString)
	if err != nil {
		http.Error(w, "Token invalide", http.StatusUnauthorized)
		return
	}

	// Récupérer l'utilisateur
	var user models.User
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}
	if user.Type == nil || (*user.Type == "user") {
		http.Error(w, "Accès refusé", http.StatusForbidden)
		return
	}

	// Récupérer l'ID de l'étape
	stepIDStr := strings.TrimPrefix(r.URL.Path, "/step/")
	stepID, err := primitive.ObjectIDFromHex(stepIDStr)
	if err != nil {
		http.Error(w, "ID de step invalide", http.StatusBadRequest)
		return
	}

	// Body à mettre à jour
	var updatedStep models.Step
	if err := json.NewDecoder(r.Body).Decode(&updatedStep); err != nil {
		http.Error(w, "Corps invalide", http.StatusBadRequest)
		return
	}

	updateFields := bson.M{}
	if updatedStep.Title != nil {
		updateFields["title"] = updatedStep.Title
	}
	if updatedStep.Subtitle != nil {
		updateFields["subtitle"] = updatedStep.Subtitle
	}
	if updatedStep.Description != nil {
		updateFields["description"] = updatedStep.Description
	}
	if updatedStep.Roadmaps != nil {
		updateFields["Roadmaps"] = updatedStep.Roadmaps
	}
	if updatedStep.Contents != nil {
		updateFields["Contents"] = updatedStep.Contents
	}
	if updatedStep.PreviousSteps != nil {
		updateFields["PreviousSteps"] = updatedStep.PreviousSteps
	}
	if updatedStep.NextSteps != nil {
		updateFields["NextSteps"] = updatedStep.NextSteps
	}
	updateFields["UpdatedAt"] = time.Now()
	updateFields["UpdatedBy"] = user.ID

	// Si aucun champ modifié
	if len(updateFields) == 0 {
		http.Error(w, "Aucun champ valide à modifier", http.StatusBadRequest)
		return
	}

	stepCollection := database.Client.Database("smashheredb").Collection("step")
	filter := bson.M{"_id": stepID}
	update := bson.M{"$set": updateFields}
	result, err := stepCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour", http.StatusInternalServerError)
		return
	}
	if result.MatchedCount == 0 {
		http.Error(w, "Aucune étape trouvée", http.StatusNotFound)
		return
	}

	// Réponse OK
	json.NewEncoder(w).Encode(map[string]any{
		"message":    "Étape modifiée avec succès",
		"updated_at": time.Now(),
		"modified":   result.ModifiedCount,
	})
}

// Supprimer une étape
func deleteOneStep(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
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
		http.Error(w, "Accès refusé : Vous n'avez pas les permissions pour supprimer une roadmap", http.StatusForbidden)
		return
	}

	// Extraire l'id de l'étape du chemin
	stepIdFromPath := strings.TrimPrefix(r.URL.Path, "/step/")
	stepID, err := primitive.ObjectIDFromHex(stepIdFromPath)
	if err != nil {
		// log.Printf("ID de la step invalide", stepIdFromPath)
		http.Error(w, "ID de l'étape invalide", http.StatusBadRequest)
		return
	}

	// Supprimer l'étape
	stepCollection := database.Client.Database("smashheredb").Collection("step")
	result, err := stepCollection.DeleteOne(context.Background(), bson.M{"_id": stepID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Supprimer l'étape des roadmaps
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	roadmapCollection.UpdateMany(
		ctx,
		bson.M{"Steps": stepID},
		bson.M{"$pull": bson.M{"Steps": stepID}},
	)

	json.NewEncoder(w).Encode(result)
	w.Write([]byte("Étape supprimée avec succès"))
}

// Ajouter une étape à une liste de roadmaps
func addStepToRoadmaps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
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
		http.Error(w, "Accès refusé : Vous n'avez pas les permissions pour ajouter une étape à des roadmaps", http.StatusForbidden)
		return
	}

	// Extraire l’ID de roadmap depuis l’URL
	pathParts := strings.Split(r.URL.Path, "/")

	if len(pathParts) < 4 || pathParts[3] != "roadmaps" {
		http.Error(w, "URL invalide", http.StatusBadRequest)
		return
	}

	stepIDStr := pathParts[2]

	stepID, err := primitive.ObjectIDFromHex(stepIDStr)
	if err != nil {
		http.Error(w, "ID de l'étape invalide", http.StatusBadRequest)
		return
	}

	// Vérifier que l'étape existe
	stepCollection := database.Client.Database("smashheredb").Collection("step")
	var step models.Step
	err = stepCollection.FindOne(ctx, bson.M{"_id": stepID}).Decode(&step)
	if err != nil {
		http.Error(w, "L'étape spécifiée n'existe pas", http.StatusNotFound)
		return
	}

	// Récupérer les jeux depuis le body
	var payload struct {
		RoadmapIDs []string `json:"Roadmaps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Format du body invalide", http.StatusBadRequest)
		return
	}

	// Conversion en ObjectID
	var roadmapObjectIDs []primitive.ObjectID
	for _, idStr := range payload.RoadmapIDs {
		roadmapID, err := primitive.ObjectIDFromHex(idStr)
		if err != nil {
			http.Error(w, fmt.Sprintf("ID de jeu invalide : %s", idStr), http.StatusBadRequest)
			return
		}
		roadmapObjectIDs = append(roadmapObjectIDs, roadmapID)
	}

	// Mise à jour de l'étape
	result, err := stepCollection.UpdateOne(ctx, bson.M{"_id": stepID}, bson.M{
		"$set": bson.M{
			"Roadmaps":  roadmapObjectIDs,
			"UpdatedAt": time.Now(),
			"UpdatedBy": user.ID,
		},
	})
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour de l'étape", http.StatusInternalServerError)
		return
	}
	if result.MatchedCount == 0 {
		http.Error(w, "Aucune étape mise à jour", http.StatusNotFound)
		return
	}

	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	for _, roadmapID := range roadmapObjectIDs {
		res, err := roadmapCollection.UpdateOne(ctx, bson.M{"_id": roadmapID}, bson.M{
			"$addToSet": bson.M{
				"Steps": stepID,
			},
			"$set": bson.M{
				"UpdatedAt": time.Now(),
				"UpdatedBy": user.ID,
			},
		})
		if err != nil {
			http.Error(w, fmt.Sprintf("Erreur lors de la mise à jour du jeu : %s", stepID.Hex()), http.StatusInternalServerError)
			return
		}
		if res.MatchedCount == 0 {
			log.Printf("Aucun jeu trouvé pour l'ID %s\n", stepID.Hex())
		}
	}

	json.NewEncoder(w).Encode(map[string]any{
		"message":         "Étape et jeux mis à jour avec succès",
		"step_id":         stepID.Hex(),
		"linked_roadmaps": payload.RoadmapIDs,
		"updated_by":      user.Email,
		"updated_at":      time.Now(),
	})
}

/* ---------- CONTENUS  ---------- */

// Créer un contenu
func createContent(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "Accès refusé : Vous n'avez pas les permissions pour créer une étape", http.StatusForbidden)
		return
	}

	// Décoder l'étape reçue en JSON
	var content models.Content
	err = json.NewDecoder(r.Body).Decode(&content)
	if err != nil {
		http.Error(w, "Format de données invalide", http.StatusBadRequest)
		return
	}

	// Validation des champs obligatoires
	if content.Title == nil || content.Type == nil || content.Link == nil {
		http.Error(w, "Le titre, type et le lien sont obligatoires", http.StatusBadRequest)
		return
	}

	// Initialisation des champs du contenu
	content.ID = primitive.NewObjectID()
	content.CreatedBy = user.ID
	content.UpdatedBy = user.ID
	content.CreatedAt = time.Now()
	content.UpdatedAt = time.Now()

	// Insérer le contenu en base de données
	contentCollection := database.Client.Database("smashheredb").Collection("content")
	_, err = contentCollection.InsertOne(ctx, content)
	if err != nil {
		http.Error(w, "Erreur lors de l'ajout du contenu", http.StatusInternalServerError)
		return
	}

	// Réponse de succès
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Contenu créé avec succès"})
}

// Récupérer un contenu
func getOneContent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	contentIdFromPath := strings.TrimPrefix(r.URL.Path, "/content/")
	contentID, err := primitive.ObjectIDFromHex(contentIdFromPath)
	if err != nil {
		http.Error(w, "ID du contenu invalide", http.StatusBadRequest)
		return
	}

	// Vérifier que le contenu existe
	contentCollection := database.Client.Database("smashheredb").Collection("content")
	var content models.Content
	err = contentCollection.FindOne(ctx, bson.M{"_id": contentID}).Decode(&content)
	if err != nil {
		http.Error(w, "La content spécifiée n'existe pas", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(content)
}

// Récupérer tous les contenus
func getAllContents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
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
		http.Error(w, "Accès refusé : Vous n'avez pas les permissions pour récupérer tous les contenus", http.StatusForbidden)
		return
	}

	// Vérifier que le contenu existe
	var contents []models.Content
	contentCollection := database.Client.Database("smashheredb").Collection("content")
	cursor, err := contentCollection.Find(context.Background(), bson.D{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var content models.Content
		if err := cursor.Decode(&content); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		contents = append(contents, content)
	}

	json.NewEncoder(w).Encode(contents)
}

// Récupérer les contenus d'un utilisateur
func getUserContents(w http.ResponseWriter, r *http.Request) {
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
	email, err := extractEmailFromToken(tokenString)
	if err != nil {
		http.Error(w, "Token invalide", http.StatusUnauthorized)
		return
	}

	// Récupérer l'utilisateur
	var user models.User
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}

	// Charger les contenus
	contentCollection := database.Client.Database("smashheredb").Collection("content")
	cursor, err := contentCollection.Find(ctx, bson.M{"_id": bson.M{"$in": user.RoadmapsCreated}})
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des contenus", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var contents []models.Content
	if err := cursor.All(ctx, &contents); err != nil {
		http.Error(w, "Erreur lors du parsing des données", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(contents)
}

// Modifier un contenu
func updateOneContent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
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
	email, err := extractEmailFromToken(tokenString)
	if err != nil {
		http.Error(w, "Token invalide", http.StatusUnauthorized)
		return
	}

	// Récupérer l'utilisateur
	var user models.User
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}

	if user.Type == nil || (*user.Type == "user") {
		http.Error(w, "Accès refusé", http.StatusForbidden)
		return
	}

	// Récupérer l'ID du contenu
	contentIDStr := strings.TrimPrefix(r.URL.Path, "/content/")
	contentID, err := primitive.ObjectIDFromHex(contentIDStr)
	if err != nil {
		http.Error(w, "ID du contenu invalide", http.StatusBadRequest)
		return
	}

	// Body à mettre à jour
	var updatedContent models.Content
	if err := json.NewDecoder(r.Body).Decode(&updatedContent); err != nil {
		http.Error(w, "Corps invalide", http.StatusBadRequest)
		return
	}

	updateFields := bson.M{}
	if updatedContent.Title != nil {
		updateFields["title"] = updatedContent.Title
	}
	if updatedContent.Type != nil {
		updateFields["type"] = updatedContent.Type
	}
	if updatedContent.Link != nil {
		updateFields["link"] = updatedContent.Link
	}
	if updatedContent.Steps != nil {
		updateFields["Steps"] = updatedContent.Steps
	}
	updateFields["UpdatedAt"] = time.Now()
	updateFields["UpdatedBy"] = user.ID

	// Si aucun champ modifié
	if len(updateFields) == 0 {
		http.Error(w, "Aucun champ valide à modifier", http.StatusBadRequest)
		return
	}

	contentCollection := database.Client.Database("smashheredb").Collection("content")
	filter := bson.M{"_id": contentID}
	update := bson.M{"$set": updateFields}
	result, err := contentCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour", http.StatusInternalServerError)
		return
	}
	if result.MatchedCount == 0 {
		http.Error(w, "Aucun contenu trouvé", http.StatusNotFound)
		return
	}

	// Réponse OK
	json.NewEncoder(w).Encode(map[string]any{
		"message":    "Contenu modifié avec succès",
		"updated_at": time.Now(),
		"modified":   result.ModifiedCount,
	})
}

// Ajouter un contenu à une liste d'étapes
func addContentToSteps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
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
		http.Error(w, "Accès refusé : Vous n'avez pas les permissions pour ajouter un contenu à une étape", http.StatusForbidden)
		return
	}

	// Extraire l’ID de roadmap depuis l’URL
	pathParts := strings.Split(r.URL.Path, "/")

	if len(pathParts) < 4 || pathParts[3] != "steps" {
		http.Error(w, "URL invalide", http.StatusBadRequest)
		return
	}

	contentIDStr := pathParts[2]

	contentID, err := primitive.ObjectIDFromHex(contentIDStr)
	if err != nil {
		http.Error(w, "ID de roadmap invalide", http.StatusBadRequest)
		return
	}

	// Vérifier que la roadmap existe
	contentCollection := database.Client.Database("smashheredb").Collection("content")
	var content models.Content
	err = contentCollection.FindOne(ctx, bson.M{"_id": contentID}).Decode(&content)
	if err != nil {
		http.Error(w, "La roadmap spécifiée n'existe pas", http.StatusNotFound)
		return
	}

	// Récupérer les jeux depuis le body
	var payload struct {
		StepIDs []string `json:"Steps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Format du body invalide", http.StatusBadRequest)
		return
	}

	// Conversion en ObjectID
	var stepObjectIDs []primitive.ObjectID
	for _, idStr := range payload.StepIDs {
		stepID, err := primitive.ObjectIDFromHex(idStr)
		if err != nil {
			http.Error(w, fmt.Sprintf("ID de jeu invalide : %s", idStr), http.StatusBadRequest)
			return
		}
		stepObjectIDs = append(stepObjectIDs, stepID)
	}

	// Mise à jour de la roadmap
	result, err := contentCollection.UpdateOne(ctx, bson.M{"_id": contentID}, bson.M{
		"$set": bson.M{
			"Steps":     stepObjectIDs,
			"UpdatedAt": time.Now(),
			"UpdatedBy": user.ID,
		},
	})
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour de la roadmap", http.StatusInternalServerError)
		return
	}
	if result.MatchedCount == 0 {
		http.Error(w, "Aucune roadmap mise à jour", http.StatusNotFound)
		return
	}

	stepCollection := database.Client.Database("smashheredb").Collection("step")
	for _, stepID := range stepObjectIDs {
		res, err := stepCollection.UpdateOne(ctx, bson.M{"_id": stepID}, bson.M{
			"$addToSet": bson.M{
				"Contents": contentID,
			},
			"$set": bson.M{
				"UpdatedAt": time.Now(),
				"UpdatedBy": user.ID,
			},
		})
		if err != nil {
			http.Error(w, fmt.Sprintf("Erreur lors de la mise à jour du jeu : %s", stepID.Hex()), http.StatusInternalServerError)
			return
		}
		if res.MatchedCount == 0 {
			log.Printf("Aucun jeu trouvé pour l'ID %s\n", stepID.Hex())
		}
	}

	json.NewEncoder(w).Encode(map[string]any{
		"message":      "Roadmap et jeux mis à jour avec succès",
		"content_id":   contentID.Hex(),
		"linked_steps": payload.StepIDs,
		"updated_by":   user.Email,
		"updated_at":   time.Now(),
	})
}

// Supprimer un contenu
func deleteOneContent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
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
		http.Error(w, "Accès refusé : Vous n'avez pas les permissions pour supprimer une roadmap", http.StatusForbidden)
		return
	}

	// Extraire l'id du contenu du chemin
	contentIdFromPath := strings.TrimPrefix(r.URL.Path, "/content/")
	contentID, err := primitive.ObjectIDFromHex(contentIdFromPath)
	if err != nil {
		http.Error(w, "ID du contenu invalide", http.StatusBadRequest)
		return
	}

	// Supprimer le contenu
	contentCollection := database.Client.Database("smashheredb").Collection("content")
	result, err := contentCollection.DeleteOne(context.Background(), bson.M{"_id": contentID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Supprimer le contenu des étapes
	stepCollection := database.Client.Database("smashheredb").Collection("step")
	stepCollection.UpdateMany(
		ctx,
		bson.M{"Contents": contentID},
		bson.M{"$pull": bson.M{"Contents": contentID}},
	)

	json.NewEncoder(w).Encode(result)
	w.Write([]byte("Contenu supprimé avec succès"))
}

/* ---------- TAGS (superadmin)  ---------- */

// Créer un tag
func createTag(w http.ResponseWriter, r *http.Request) {
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
	if user.Type == nil || (*user.Type == "user") || (*user.Type == "coach") {
		http.Error(w, "Accès refusé : Vous n'avez pas les permissions pour créer une roadmap", http.StatusForbidden)
		return
	}

	// Décoder reçue en JSON
	var tag models.Tag
	err = json.NewDecoder(r.Body).Decode(&tag)
	if err != nil {
		http.Error(w, "Format de données invalide", http.StatusBadRequest)
		return
	}

	// Validation des champs obligatoires
	if tag.Name == nil {
		http.Error(w, "Le nom est obligatoire", http.StatusBadRequest)
		return
	}

	// Initialisation des champs de la tag
	tag.ID = primitive.NewObjectID()
	tag.CreatedBy = user.ID
	tag.UpdatedBy = user.ID
	tag.CreatedAt = time.Now()
	tag.UpdatedAt = time.Now()

	// Insérer le tag en base de données
	collection := database.Client.Database("smashheredb").Collection("tag")
	_, err = collection.InsertOne(ctx, tag)
	if err != nil {
		http.Error(w, "Erreur lors de l'ajout du tag", http.StatusInternalServerError)
		return
	}

	// Réponse de succès
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Tag créé avec succès"})
}

// Ajouter un tag à plusieurs roadmaps
func addTagToRoadmaps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
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
	email, err := extractEmailFromToken(tokenString)
	if err != nil {
		http.Error(w, "Token invalide", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Récupérer l'utilisateur
	var user models.User
	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}
	if user.Type == nil || (*user.Type == "user") || (*user.Type == "coach") {
		http.Error(w, "Accès refusé", http.StatusForbidden)
		return
	}

	// Extraire l'ID du tag depuis l'URL
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 5 || pathParts[4] != "roadmaps" {
		http.Error(w, "URL invalide", http.StatusBadRequest)
		return
	}
	tagIDStr := pathParts[3]
	tagID, err := primitive.ObjectIDFromHex(tagIDStr)
	if err != nil {
		http.Error(w, "ID de tag invalide", http.StatusBadRequest)
		return
	}

	// Vérifier que le tag existe
	tagCollection := database.Client.Database("smashheredb").Collection("tag")
	var tag models.Tag
	err = tagCollection.FindOne(ctx, bson.M{"_id": tagID}).Decode(&tag)
	if err != nil {
		http.Error(w, "Tag introuvable", http.StatusNotFound)
		return
	}

	// Récupérer la liste des IDs des roadmaps à modifier
	var payload struct {
		RoadmapIDs []string `json:"roadmaps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Body invalide", http.StatusBadRequest)
		return
	}

	var objectIDs []primitive.ObjectID
	for _, idStr := range payload.RoadmapIDs {
		objID, err := primitive.ObjectIDFromHex(idStr)
		if err != nil {
			http.Error(w, "ID de roadmap invalide : "+idStr, http.StatusBadRequest)
			return
		}
		objectIDs = append(objectIDs, objID)
	}

	// Mise à jour en batch : ajout du tag à chaque roadmap
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	_, err = roadmapCollection.UpdateMany(ctx,
		bson.M{"_id": bson.M{"$in": objectIDs}},
		bson.M{"$addToSet": bson.M{"Tags": tagID}},
	)
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour des roadmaps", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"message":    "Tag ajouté aux roadmaps avec succès",
		"tag_id":     tagID.Hex(),
		"roadmaps":   payload.RoadmapIDs,
		"updated_by": user.Email,
		"updated_at": time.Now(),
	})
}

// Récupérer tous les tags
func getAllTags(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Vérifier que le tag existe
	var tags []models.Tag
	tagCollection := database.Client.Database("smashheredb").Collection("tag")
	cursor, err := tagCollection.Find(context.Background(), bson.D{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var tag models.Tag
		if err := cursor.Decode(&tag); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tags = append(tags, tag)
	}

	json.NewEncoder(w).Encode(tags)
}

// Supprimer un tag
func deleteOneTag(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
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
	if user.Type == nil || (*user.Type == "user") || (*user.Type == "coach") {
		http.Error(w, "Accès refusé : Vous n'avez pas les permissions pour supprimer un tag", http.StatusForbidden)
		return
	}

	// Extraire l'id du contenu du chemin
	tagIdFromPath := strings.TrimPrefix(r.URL.Path, "/superadmin/tag/")
	tagID, err := primitive.ObjectIDFromHex(tagIdFromPath)
	if err != nil {
		http.Error(w, "ID du tag invalide", http.StatusBadRequest)
		return
	}

	// Supprimer le tag
	tagCollection := database.Client.Database("smashheredb").Collection("tag")
	result, err := tagCollection.DeleteOne(context.Background(), bson.M{"_id": tagID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Supprimer le tag des roadmaps
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	roadmapCollection.UpdateMany(
		ctx,
		bson.M{"Tags": tagID},
		bson.M{"$pull": bson.M{"Tags": tagID}},
	)

	json.NewEncoder(w).Encode(result)
}

// Modifier un tag
func updateOneTag(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
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
	email, err := extractEmailFromToken(tokenString)
	if err != nil {
		http.Error(w, "Token invalide", http.StatusUnauthorized)
		return
	}

	// Récupérer l'utilisateur
	var user models.User
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}

	if user.Type == nil || (*user.Type == "user") || (*user.Type == "coach") {
		http.Error(w, "Accès refusé", http.StatusForbidden)
		return
	}

	// Récupérer l'ID du tag
	tagIDStr := strings.TrimPrefix(r.URL.Path, "/superadmin/tag/")
	tagID, err := primitive.ObjectIDFromHex(tagIDStr)
	if err != nil {
		http.Error(w, "ID du tag invalide", http.StatusBadRequest)
		return
	}

	// Body à mettre à jour
	var updatedTag models.Tag
	if err := json.NewDecoder(r.Body).Decode(&updatedTag); err != nil {
		http.Error(w, "Corps invalide", http.StatusBadRequest)
		return
	}

	updateFields := bson.M{}
	if updatedTag.Name != nil {
		updateFields["name"] = updatedTag.Name
	}
	updateFields["UpdatedAt"] = time.Now()
	updateFields["UpdatedBy"] = user.ID

	// Si aucun champ modifié
	if len(updateFields) == 0 {
		http.Error(w, "Aucun champ valide à modifier", http.StatusBadRequest)
		return
	}

	tagCollection := database.Client.Database("smashheredb").Collection("tag")
	filter := bson.M{"_id": tagID}
	update := bson.M{"$set": updateFields}
	result, err := tagCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour", http.StatusInternalServerError)
		return
	}
	if result.MatchedCount == 0 {
		http.Error(w, "Aucun tag trouvé", http.StatusNotFound)
		return
	}

	// Réponse OK
	json.NewEncoder(w).Encode(map[string]any{
		"message":    "Tag modifié avec succès",
		"updated_at": time.Now(),
		"modified":   result.ModifiedCount,
	})
}
