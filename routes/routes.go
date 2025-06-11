package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/StevenYAMBOS/Smash-Here-API/database"
	"github.com/StevenYAMBOS/Smash-Here-API/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
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

func parseObjectIDArray(input string) ([]primitive.ObjectID, error) {
	ids := strings.Split(input, ",")
	var objectIDs []primitive.ObjectID
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		oid, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			return nil, err
		}
		objectIDs = append(objectIDs, oid)
	}
	return objectIDs, nil
}

/* ==================== ROUTEUR ==================== */

func Router() *http.ServeMux {
	mux := http.NewServeMux()

	// Authentification
	mux.HandleFunc("/", home)
	mux.HandleFunc("/test", testS3Connexion)
	mux.HandleFunc("POST /auth/register", register)
	mux.HandleFunc("POST /auth/login", login)
	// Utilisateur
	mux.HandleFunc("GET /user/roadmaps", AuthMiddleware(getUserRoadmaps))
	mux.HandleFunc("GET /user/bookmarks", AuthMiddleware(getUserBookmarks))
	mux.HandleFunc("GET /user/comments", AuthMiddleware(getUserComments))
	mux.HandleFunc("POST /roadmap/{id}/comments", AuthMiddleware(addCommentToRoadmap))
	mux.HandleFunc("GET /roadmap/{id}/comments", AuthMiddleware(getRoadmapComments))
	mux.HandleFunc("PUT /user/bookmarks", AuthMiddleware(addRoadmapToBookmarks))
	mux.HandleFunc("PUT /user/profile", AuthMiddleware(updateProfile))
	mux.HandleFunc("GET /user/profile", AuthMiddleware(getProfile))
	mux.HandleFunc("DELETE /user/bookmarks", AuthMiddleware(removeRoadmapToBookmarks))
	mux.HandleFunc("DELETE /roadmap/{roadmapId}/comment/{commentId}", AuthMiddleware(deleteCommentToRoadmap))
	mux.HandleFunc("PUT /roadmap/{roadmapId}/comment/{commentId}", AuthMiddleware(updateCommentToRoadmap))
	mux.HandleFunc("DELETE /user", AuthMiddleware(deleteCurrentUser))
	mux.HandleFunc("GET /user/{id}", AuthMiddleware(getUserById))
	mux.HandleFunc("POST /contact", addContact)
	// Roadmap
	mux.HandleFunc("POST /roadmap", AuthMiddleware(createRoadmap))
	mux.HandleFunc("POST /superadmin/roadmap", AuthMiddleware(createSmashHereRoadmap))
	mux.HandleFunc("PUT /roadmap/{id}", AuthMiddleware(updateOneRoadmap))
	mux.HandleFunc("PUT /roadmap/{id}/info", AuthMiddleware(updateRoadmapInfo))
	mux.HandleFunc("PUT /roadmap/{id}/steps", AuthMiddleware(updateRoadmapSteps))
	mux.HandleFunc("GET /roadmap/{id}", getRoadmap)
	mux.HandleFunc("GET /roadmap/{id}/steps", getRoadmapSteps)
	mux.HandleFunc("GET /superadmin/roadmaps", AuthMiddleware(getAllRoadmaps))
	mux.HandleFunc("GET /roadmaps", getAllPublishedRoadmaps)
	mux.HandleFunc("PUT /roadmap/{id}/games", AuthMiddleware(addRoadmapToGames))
	mux.HandleFunc("PUT /roadmap/{id}/remove-tags", AuthMiddleware(removeTagsFromRoadmap))
	mux.HandleFunc("DELETE /roadmap/{id}", AuthMiddleware(deleteOneRoadmap))
	mux.HandleFunc("DELETE /roadmap/{id}/step/{stepId}", AuthMiddleware(removeStepFromRoadmap))
	mux.HandleFunc("PATCH /roadmap/{id}/publish", AuthMiddleware(publishRoadmap))
	mux.HandleFunc("PATCH /roadmap/{id}/premium", AuthMiddleware(setRoadmapPremium))
	// Étapes
	mux.HandleFunc("POST /step", AuthMiddleware(createStep))
	mux.HandleFunc("PUT /step/{id}", AuthMiddleware(updateOneStep))
	mux.HandleFunc("PUT /steps/{id}/roadmaps", AuthMiddleware(addStepToRoadmaps))
	mux.HandleFunc("GET /step/{id}", getOneStep)
	mux.HandleFunc("GET /step/{id}/contents", getContentsFromStep)
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
	mux.HandleFunc("GET /game/{id}", getGame)
	mux.HandleFunc("GET /games", getAllGames)
	mux.HandleFunc("POST /superadmin/game", AuthMiddleware(createGame))
	mux.HandleFunc("PUT /superadmin/game/{id}", AuthMiddleware(updateOneGame))
	mux.HandleFunc("GET /game/{id}/roadmaps", getRoadmapsFromGame)
	mux.HandleFunc("DELETE /game/{id}/roadmaps", AuthMiddleware(removeRoadmapsFromGame))

	return mux
}

/* ==================== ROUTES  ==================== */

// Route principale
func home(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Bienvenue sur Smash Here"))
}

// Test connexion au bucket AWS
func testS3Connexion(w http.ResponseWriter, _ *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := database.S3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(os.Getenv("AWS_S3_BUCKET_NAME")),
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Impossible d’accéder au bucket S3 : %v", err), http.StatusInternalServerError)
		return
	}
	w.Write([]byte("Connexion S3 réussie"))
}

/* ---------- AUTHENTIFICATION  ---------- */

// Inscription
func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Lire les données multipart (image + champs)
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Erreur de parsing multipart", http.StatusBadRequest)
		return
	}

	// Champs texte
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	if username == "" || email == "" || password == "" {
		http.Error(w, "Tous les champs sont obligatoires", http.StatusBadRequest)
		return
	}

	// Pseudo pas plus long que 30 caractères
	if len(username) > 30 {
		http.Error(w, "Le pseudo est trop long", http.StatusBadRequest)
	}

	// Vérifie que le pseudo contient au moins une lettre
	matched, _ := regexp.MatchString(`[A-Za-z]`, username)
	if !matched {
		http.Error(w, "Le pseudo doit contenir au moins une lettre", http.StatusBadRequest)
		return
	}

	if len(password) < 6 {
		http.Error(w, "Le mot de passe doit contenir au moins 6 caractères", http.StatusBadRequest)
		return
	}

	// Traitement de l'image (champ `image`)
	file, fileHeader, err := r.FormFile("profilePicture")
	if err != nil {
		http.Error(w, "Image manquante ou invalide", http.StatusBadRequest)
		return
	}
	defer file.Close()

	imageData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Erreur de lecture de l'image", http.StatusInternalServerError)
		return
	}

	// Nom du fichier S3
	ext := filepath.Ext(fileHeader.Filename)
	objectKey := fmt.Sprintf("user/%s%s", username, ext)

	// Upload sur S3
	s3Uploader := database.BucketBasics{S3Client: database.S3Client}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = s3Uploader.UploadLargeObject(ctx, os.Getenv("AWS_S3_BUCKET_NAME"), objectKey, imageData)
	if err != nil {
		http.Error(w, "Erreur d'upload sur S3", http.StatusInternalServerError)
		return
	}

	// URL de l'image
	imageURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s",
		os.Getenv("AWS_S3_BUCKET_NAME"),
		os.Getenv("AWS_REGION"),
		objectKey,
	)

	// Hash du mot de passe
	hashed := HashPassword(password)

	// Construction de l'utilisateur
	user := models.User{
		ID:             primitive.NewObjectID(),
		Username:       &username,
		Email:          &email,
		Password:       &hashed,
		ProfilePicture: &imageURL,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		LastLogin:      time.Now(),
	}

	userCollection := database.Client.Database("smashheredb").Collection("user")

	// Vérifie que le pseudo n'est pas déjà utilisé
	count, err := userCollection.CountDocuments(ctx, bson.M{"username": username})
	if err != nil {
		http.Error(w, "Erreur lors de la vérification du pseudo", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Error(w, "Pseudo déjà utilisé", http.StatusBadRequest)
		return
	}

	// Insertion dans MongoDB
	_, err = userCollection.InsertOne(r.Context(), user)
	if err != nil {
		http.Error(w, "Erreur lors de l'enregistrement", http.StatusInternalServerError)
		return
	}

	// Réponse
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"message":        "Utilisateur créé avec succès",
		"profilePicture": imageURL,
	})
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

// Récupérer les informations du profil
func getProfile(w http.ResponseWriter, r *http.Request) {
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

	userCollection := database.Client.Database("smashheredb").Collection("user")
	err = userCollection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}

	// Récupérer l'utilisateur connecté
	cursor, err := userCollection.Find(ctx, bson.M{"_id": user.ID})
	if err != nil {
		http.Error(w, "Erreur lors de la récupération de l'utilisateur", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	json.NewEncoder(w).Encode(user)
}

// Modifier le profil
func updateProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Lire les données multipart (image + champs)
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Erreur de parsing multipart", http.StatusBadRequest)
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

	// Body à mettre à jour
	username := r.FormValue("username")

	// Pseudo pas plus long que 30 caractères
	if len(username) > 30 {
		http.Error(w, `{"error":"Le pseudo est trop long (max 30 caractères)"}`, http.StatusBadRequest)
		return

	}

	// Vérifie que le pseudo contient au moins une lettre
	matched, _ := regexp.MatchString(`[A-Za-z]`, username)
	if !matched {
		http.Error(w, `{"error":"Le pseudo doit contenir au moins une lettre"}`, http.StatusBadRequest)
		return
	}

	// Construction du $set dynamique
	updateFields := bson.M{}

	// Traitement de l'image (champ `image`)
	file, fileHeader, err := r.FormFile("profilePicture")
	if err == nil {
		defer file.Close()
		imageData, _ := io.ReadAll(file)
		ext := filepath.Ext(fileHeader.Filename)
		objectKey := fmt.Sprintf("user/%s%s", *user.Username, ext)

		s3Uploader := database.BucketBasics{S3Client: database.S3Client}
		err = s3Uploader.UploadLargeObject(ctx, os.Getenv("AWS_S3_BUCKET_NAME"), objectKey, imageData)
		if err == nil {
			imageURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s",
				os.Getenv("AWS_S3_BUCKET_NAME"),
				os.Getenv("AWS_REGION"),
				objectKey,
			)
			updateFields["profilePicture"] = imageURL
		}
	}

	if username != "" {
		updateFields["username"] = username
	}
	updateFields["UpdatedAt"] = time.Now()
	updateFields["UpdatedBy"] = user.ID

	// Si aucun champ modifié
	if len(updateFields) == 0 {
		http.Error(w, "Aucun champ valide à modifier", http.StatusBadRequest)
		return
	}

	// Vérifie que le pseudo n'est pas déjà utilisé
	if username != *user.Username {
		count, err := userCollection.CountDocuments(ctx, bson.M{"username": username})
		if err != nil {
			http.Error(w, `{"error":"Erreur lors de la vérification du pseudo"}`, http.StatusInternalServerError)
			return
		}
		if count > 0 {
			http.Error(w, `{"error":"Pseudo déjà utilisé"}`, http.StatusBadRequest)
			return
		}
	}

	filter := bson.M{"_id": user.ID}
	update := bson.M{"$set": updateFields}
	result, err := userCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour", http.StatusInternalServerError)
		return
	}
	if result.MatchedCount == 0 {
		http.Error(w, "Aucune utilisateur trouvé", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"message":    "Utilisateur modifié avec succès",
		"updated_at": time.Now(),
		"modified":   result.ModifiedCount,
	})
}

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

// Récupérer les bookmarks d'un utilisateur
func getUserBookmarks(w http.ResponseWriter, r *http.Request) {
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

	// Récupérer les roadmaps de l'utilisateur depuis le champ `Bookmarks`
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	cursor, err := roadmapCollection.Find(ctx, bson.M{"_id": bson.M{"$in": user.Bookmarks}})
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

// Modifier un commentaire sur une roadmap
func updateCommentToRoadmap(w http.ResponseWriter, r *http.Request) {
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
	if user.ID.IsZero() {
		http.Error(w, "Utilisateur invalide", http.StatusForbidden)
		return
	}

	// Extraire l’ID de roadmap et l’ID de commentaire depuis l’URL
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 5 || pathParts[1] != "roadmap" || pathParts[3] != "comment" {
		http.Error(w, "URL invalide", http.StatusBadRequest)
		return
	}

	roadmapIDStr := pathParts[2]
	commentIDStr := pathParts[4]

	roadmapID, err := primitive.ObjectIDFromHex(roadmapIDStr)
	if err != nil {
		http.Error(w, "ID de roadmap invalide", http.StatusBadRequest)
		return
	}
	commentID, err := primitive.ObjectIDFromHex(commentIDStr)
	if err != nil {
		http.Error(w, "ID du commentaire invalide", http.StatusBadRequest)
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
	var updatedComment models.Comment
	err = json.NewDecoder(r.Body).Decode(&updatedComment)
	if err != nil {
		http.Error(w, "Format de données invalide", http.StatusBadRequest)
		return
	}

	updateFields := bson.M{}
	if updatedComment.Message != nil {
		updateFields["message"] = updatedComment.Message
	}
	// Champs automatiques
	updateFields["UpdatedAt"] = time.Now()
	updateFields["UpdatedBy"] = user.ID

	// Si aucun champ modifié
	if len(updateFields) == 0 {
		http.Error(w, "Aucun champ valide à modifier", http.StatusBadRequest)
		return
	}

	// Collection commentaire (`comment`)
	commentCollection := database.Client.Database("smashheredb").Collection("comment")
	filter := bson.M{"_id": commentID}
	update := bson.M{"$set": updateFields}
	result, err := commentCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour", http.StatusInternalServerError)
		return
	}
	if result.MatchedCount == 0 {
		http.Error(w, "Aucun commentaire trouvé", http.StatusNotFound)
		return
	}

	// Réponse OK
	json.NewEncoder(w).Encode(map[string]any{
		"message":    "Roadmap modifiée avec succès",
		"updated_at": time.Now(),
		"modified":   result.ModifiedCount,
	})
}

// Récupérer les commentaires d'un utilisateur
func getUserComments(w http.ResponseWriter, r *http.Request) {
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

	// Vérifier le rôle de l'utilisateur
	if user.ID.IsZero() {
		http.Error(w, "Utilisateur invalide", http.StatusForbidden)
		return
	}

	// Lire les paramètres de pagination depuis l'URL
	limitParam := r.URL.Query().Get("limit")
	skipParam := r.URL.Query().Get("skip")

	limit := int64(10)
	skip := int64(0)

	if limitParam != "" {
		if parsed, err := strconv.ParseInt(limitParam, 10, 64); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if skipParam != "" {
		if parsed, err := strconv.ParseInt(skipParam, 10, 64); err == nil && parsed >= 0 {
			skip = parsed
		}
	}

	// Récupérer les commentaires de l'utilisateur depuis le champ `Comments`
	commentCollection := database.Client.Database("smashheredb").Collection("comment")
	totalCount, err := commentCollection.CountDocuments(ctx, bson.M{"CreatedBy": user.ID})
	if err != nil {
		http.Error(w, "Erreur lors du comptage des commentaires", http.StatusInternalServerError)
		return
	}

	cursor, err := commentCollection.Find(ctx, bson.M{
		"CreatedBy": user.ID,
	}, options.Find().
		SetSort(bson.D{{Key: "createdAt", Value: -1}}).
		SetLimit(limit).
		SetSkip(skip))

	var comments []models.Comment
	if err := cursor.All(ctx, &comments); err != nil {
		http.Error(w, "Erreur lors du parsing des données", http.StatusInternalServerError)
		return
	}

	hasMore := (skip + limit) < totalCount

	json.NewEncoder(w).Encode(map[string]any{
		"comments":   comments,
		"totalCount": totalCount,
		"limit":      limit,
		"skip":       skip,
		"hasMore":    hasMore,
	})
}

// Supprimer un commentaire d'une roadmap
func deleteCommentToRoadmap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
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
	var userCollection = database.Client.Database("smashheredb").Collection("user")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}

	// Vérification du rôle
	if user.ID.IsZero() {
		http.Error(w, "Accès refusé, vous devez être connecté.", http.StatusForbidden)
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

	// Vérification de l'existence de la roadmap
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	var roadmap models.Roadmap
	err = roadmapCollection.FindOne(ctx, bson.M{"_id": roadmapID}).Decode(&roadmap)
	if err != nil {
		http.Error(w, "Roadmap introuvable", http.StatusNotFound)
		return
	}

	// Récupérer le commentaire depuis le body
	var payload struct {
		CommentID string `json:"commentId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Format du body invalide", http.StatusBadRequest)
		return
	}

	// Transformer l'id en `ObjectId`
	commentID, err := primitive.ObjectIDFromHex(payload.CommentID)
	if err != nil {
		http.Error(w, "ID invalide", http.StatusBadRequest)
		return
	}

	// Récupérer le commentaire à supprimer
	var comment models.Comment
	commentCollection := database.Client.Database("smashheredb").Collection("comment")
	err = commentCollection.FindOne(ctx, bson.M{"_id": commentID}).Decode(&comment)
	if err != nil {
		http.Error(w, "Commentaire introuvable", http.StatusNotFound)
		return
	}

	// Supprimer le commentaire principal
	_, err = commentCollection.DeleteOne(ctx, bson.M{"_id": commentID})
	if err != nil {
		http.Error(w, "Erreur lors de la suppression du commentaire", http.StatusInternalServerError)
		return
	}

	// Supprimer aussi ses éventuelles réponses (cascade sur Responses)
	if len(comment.Responses) > 0 {
		_, err = commentCollection.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": comment.Responses}})
		if err != nil {
			http.Error(w, "Erreur lors de la suppression des réponses du commentaire", http.StatusInternalServerError)
			return
		}
	}

	// Supprimer le commentaire de la roadmap
	_, err = roadmapCollection.UpdateOne(ctx, bson.M{"_id": roadmapID}, bson.M{
		"$pull": bson.M{
			"Comments": commentID,
		},
	})
	if err != nil {
		http.Error(w, "Erreur lors de la suppression du commentaire de la roadmap", http.StatusInternalServerError)
		return
	}

	// Supprimer le commentaire de l'utilisateur
	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{
		"$pull": bson.M{
			"Comments": commentID,
		},
	})
	if err != nil {
		http.Error(w, "Erreur lors de la suppression du commentaire de l'utilisateur", http.StatusInternalServerError)
		return
	}

	// Réponse de succès
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"message": "Commentaire supprimé avec succès",
	})
}

// Supprimer son compte
func deleteCurrentUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	token := r.Header.Get("Authorization")
	if token == "" || !strings.HasPrefix(token, "Bearer ") {
		http.Error(w, "Token manquant ou invalide", http.StatusUnauthorized)
		return
	}
	email, err := extractEmailFromToken(token[7:])
	if err != nil {
		http.Error(w, "Token invalide", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user models.User
	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}

	// Vérification du rôle
	if user.ID.IsZero() {
		http.Error(w, "Accès refusé, vous devez être connecté.", http.StatusForbidden)
		return
	}

	userID := user.ID

	// Suppression des contenus associés
	database.Client.Database("smashheredb").Collection("content").DeleteMany(ctx, bson.M{"CreatedBy": userID})
	database.Client.Database("smashheredb").Collection("step").DeleteMany(ctx, bson.M{"CreatedBy": userID})
	database.Client.Database("smashheredb").Collection("roadmap").DeleteMany(ctx, bson.M{"CreatedBy": userID})
	database.Client.Database("smashheredb").Collection("comment").DeleteMany(ctx, bson.M{"User": userID})
	database.Client.Database("smashheredb").Collection("progression").DeleteMany(ctx, bson.M{"User": userID})

	// Suppression de l'utilisateur
	_, err = database.Client.Database("smashheredb").Collection("user").DeleteOne(ctx, bson.M{"_id": userID})
	if err != nil {
		http.Error(w, "Erreur lors de la suppression de l'utilisateur", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Compte supprimé avec succès",
	})
}

// Accès aux infos publiques d'un autre utilisateur (coach ou superadmin)
func getUserById(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	token := r.Header.Get("Authorization")
	if token == "" || !strings.HasPrefix(token, "Bearer ") {
		http.Error(w, "Token manquant ou invalide", http.StatusUnauthorized)
		return
	}
	email, err := extractEmailFromToken(token[7:])
	if err != nil {
		http.Error(w, "Token invalide", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var currentUser models.User
	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"email": email}).Decode(&currentUser)
	if err != nil || currentUser.Type == nil || (*currentUser.Type != "coach" && *currentUser.Type != "superadmin") {
		http.Error(w, "Accès refusé", http.StatusForbidden)
		return
	}

	userIDStr := strings.TrimPrefix(r.URL.Path, "/user/")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		http.Error(w, "ID invalide", http.StatusBadRequest)
		return
	}

	var targetUser models.User
	err = database.Client.Database("smashheredb").Collection("user").FindOne(ctx, bson.M{"_id": userID}).Decode(&targetUser)
	if err != nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusNotFound)
		return
	}

	// Masquer les données sensibles
	targetUser.Password = nil

	json.NewEncoder(w).Encode(targetUser)
}

// Envoyer le formulaire de contact
func addContact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Lire les données multipart (image + champs)
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Erreur de parsing multipart", http.StatusBadRequest)
		return
	}

	// Champs texte
	email := r.FormValue("email")
	category := r.FormValue("category")
	priority := r.FormValue("priority")
	subject := r.FormValue("subject")
	message := r.FormValue("message")

	if email == "" || category == "" || subject == "" || priority == "" || message == "" {
		http.Error(w, "Tous les champs sont obligatoires", http.StatusBadRequest)
		return
	}

	// Vérifie que l'email contient au moins une lettre
	matched, _ := regexp.MatchString(`[A-Za-z]`, email)
	if !matched {
		http.Error(w, "L'email doit contenir au moins une lettre", http.StatusBadRequest)
		return
	}

	var imageURL *string = nil

	// Traitement de l'image (champ `image`)
	file, fileHeader, err := r.FormFile("image")
	if err == nil && file != nil {
		defer file.Close()

		imageData, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, "Erreur de lecture de l'image", http.StatusInternalServerError)
			return
		}

		// Nom du fichier S3
		ext := filepath.Ext(fileHeader.Filename)
		objectKey := fmt.Sprintf("contact/%s%s", email, ext)

		// Upload sur S3
		s3Uploader := database.BucketBasics{S3Client: database.S3Client}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		err = s3Uploader.UploadLargeObject(ctx, os.Getenv("AWS_S3_BUCKET_NAME"), objectKey, imageData)
		if err != nil {
			http.Error(w, "Erreur d'upload sur S3", http.StatusInternalServerError)
			return
		}

		// URL de l'image
		imageURLStr := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s",
			os.Getenv("AWS_S3_BUCKET_NAME"),
			os.Getenv("AWS_REGION"),
			objectKey,
		)
		imageURL = &imageURLStr
	}

	contact := models.Contact{
		Email:     &email,
		Category:  &category,
		Priority:  &priority,
		Subject:   &subject,
		Message:   &message,
		Image:     imageURL,
		CreatedAt: time.Now(),
	}

	contactCollection := database.Client.Database("smashheredb").Collection("contact")

	_, err = contactCollection.InsertOne(r.Context(), contact)
	if err != nil {
		http.Error(w, "Erreur lors de l'enregistrement", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"message":                    "Formulaire de contact validé avec succès",
		"Informations du formulaire": contact,
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
	if user.Type == nil || (*user.Type != "superadmin") {
		http.Error(w, "Accès refusé : Vous n'avez pas les permissions pour créer une roadmap", http.StatusForbidden)
		return
	}

	// Lire les données multipart (image + champs)
	error := r.ParseMultipartForm(10 << 20)
	if error != nil {
		http.Error(w, "Erreur de parsing multipart", http.StatusBadRequest)
		return
	}

	// Champs texte
	title := r.FormValue("title")
	description := r.FormValue("description")
	subTitle := r.FormValue("subTitle")

	// Titre pas plus long que 30 caractères
	if len(title) > 120 {
		http.Error(w, "Le titre est trop long", http.StatusBadRequest)
		return
	}

	// Vérifie que le titre contient au moins une lettre
	matched, _ := regexp.MatchString(`[A-Za-z]`, title)
	if !matched {
		http.Error(w, "Le titre doit contenir au moins une lettre", http.StatusBadRequest)
		return
	}

	// Validation des champs obligatoires
	if title == "" || description == "" || subTitle == "" {
		http.Error(w, "Le titre, sous-titre et la description sont obligatoires", http.StatusBadRequest)
		return
	}

	// Traitement de l'image (champ `image`)
	file, fileHeader, err := r.FormFile("cover")
	if err != nil {
		http.Error(w, "Image de couverture manquante ou invalide", http.StatusBadRequest)
		return
	}
	defer file.Close()

	imageData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Erreur de lecture de l'image", http.StatusInternalServerError)
		return
	}

	// Nom du fichier S3
	ext := filepath.Ext(fileHeader.Filename)
	objectKey := fmt.Sprintf("game/%s%s", title, ext)

	// Upload sur S3
	s3Uploader := database.BucketBasics{S3Client: database.S3Client}

	err = s3Uploader.UploadLargeObject(ctx, os.Getenv("AWS_S3_BUCKET_NAME"), objectKey, imageData)
	if err != nil {
		http.Error(w, "Erreur d'upload sur S3", http.StatusInternalServerError)
		return
	}

	// URL de l'image
	coverURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s",
		os.Getenv("AWS_S3_BUCKET_NAME"),
		os.Getenv("AWS_REGION"),
		objectKey,
	)

	// Initialisation des champs du jeu
	gameFields := models.Game{
		ID:            primitive.NewObjectID(),
		CreatedBy:     user.ID,
		UpdatedBy:     user.ID,
		Title:         &title,
		Description:   &description,
		Subtitle:      &subTitle,
		Cover:         &coverURL,
		Published:     new(bool),
		ViewsPerDay:   new(int),
		ViewsPerWeek:  new(int),
		ViewsPerMonth: new(int),
		TotalViews:    new(int),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	gameCollection := database.Client.Database("smashheredb").Collection("game")

	// Vérifie que le titre du jeu n'est pas déjà utilisé
	count, err := gameCollection.CountDocuments(ctx, bson.M{"title": title})
	if err != nil {
		http.Error(w, "Erreur lors de la vérification du titre", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Error(w, "Un jeu avec ce nom existe déjà", http.StatusBadRequest)
		return
	}

	// Insérer le jeu en base de données
	_, err = gameCollection.InsertOne(ctx, gameFields)
	if err != nil {
		http.Error(w, "Erreur lors de l'ajout du jeu", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Jeu créé avec succès"})
}

// Récupérer un jeu
func getGame(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gameIdFromPath := strings.TrimPrefix(r.URL.Path, "/game/")
	gameID, err := primitive.ObjectIDFromHex(gameIdFromPath)
	if err != nil {
		http.Error(w, "ID du jeu invalide", http.StatusBadRequest)
		return
	}

	// Vérifier que le jeu existe
	gameCollection := database.Client.Database("smashheredb").Collection("game")
	var game models.Game
	err = gameCollection.FindOne(ctx, bson.M{"_id": gameID}).Decode(&game)
	if err != nil {
		http.Error(w, "Le jeu spécifiée n'existe pas", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(game)
}

// Récupérer tous les jeux
func getAllGames(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Vérifier que les jeux existent
	var games []models.Game
	gameCollection := database.Client.Database("smashheredb").Collection("game")
	cursor, err := gameCollection.Find(ctx, bson.D{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var game models.Game
		if err := cursor.Decode(&game); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		games = append(games, game)
	}

	json.NewEncoder(w).Encode(games)
}

// Modifier un jeu
func updateOneGame(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Lire les données multipart (image + champs)
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Erreur de parsing multipart", http.StatusBadRequest)
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

	// Récupérer l'ID de la game
	gameIDStr := strings.TrimPrefix(r.URL.Path, "/superadmin/game/")
	gameID, err := primitive.ObjectIDFromHex(gameIDStr)
	if err != nil {
		http.Error(w, "ID du jeu invalide", http.StatusBadRequest)
		return
	}

	// Body à mettre à jour
	title := r.FormValue("title")
	description := r.FormValue("description")
	subTitle := r.FormValue("subTitle")
	published := r.FormValue("published")

	// Construction du $set dynamique
	updateFields := bson.M{}

	// Traitement de l'image (champ `image`)
	file, fileHeader, err := r.FormFile("cover")
	if err == nil {
		defer file.Close()
		imageData, _ := io.ReadAll(file)
		ext := filepath.Ext(fileHeader.Filename)
		safeTitle := title
		if safeTitle == "" {
			safeTitle = "cover"
		}
		objectKey := fmt.Sprintf("game/%s%s", safeTitle, ext)

		s3Uploader := database.BucketBasics{S3Client: database.S3Client}
		err = s3Uploader.UploadLargeObject(ctx, os.Getenv("AWS_S3_BUCKET_NAME"), objectKey, imageData)
		if err == nil {
			coverURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s",
				os.Getenv("AWS_S3_BUCKET_NAME"),
				os.Getenv("AWS_REGION"),
				objectKey,
			)
			updateFields["cover"] = coverURL
		}
	}

	if title != "" {
		updateFields["title"] = title
	}
	if description != "" {
		updateFields["description"] = description
	}
	if subTitle != "" {
		updateFields["subTitle"] = subTitle
	}
	if published != "" {
		boolValue := published == "true"
		updateFields["published"] = boolValue
	}

	updateFields["UpdatedAt"] = time.Now()
	updateFields["UpdatedBy"] = user.ID

	// Si aucun champ modifié
	if len(updateFields) == 0 {
		http.Error(w, "Aucun champ valide à modifier", http.StatusBadRequest)
		return
	}

	filter := bson.M{"_id": gameID}
	update := bson.M{"$set": updateFields}
	gameCollection := database.Client.Database("smashheredb").Collection("game")
	result, err := gameCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour", http.StatusInternalServerError)
		return
	}
	if result.MatchedCount == 0 {
		http.Error(w, "Aucun jeu trouvé", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"message":    "Jeu modifié avec succès",
		"updated_at": time.Now(),
		"modified":   result.ModifiedCount,
	})
}

// Récupérer la liste des roadmaps d'un jeu
func getRoadmapsFromGame(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

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

// Supprimer des roadmaps d'un jeu
func removeRoadmapsFromGame(w http.ResponseWriter, r *http.Request) {
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
	if user.Type == nil || (*user.Type == "user") || (*user.Type != "superadmin") {
		http.Error(w, "Accès refusé : Vous n'avez pas les permissions pour ajouter un contenu à une étape", http.StatusForbidden)
		return
	}

	// Extraire l’ID du jeu depuis l’URL
	pathParts := strings.Split(r.URL.Path, "/")

	if len(pathParts) < 4 || pathParts[3] != "game" {
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
	var game models.Content
	err = gameCollection.FindOne(ctx, bson.M{"_id": gameID}).Decode(&game)
	if err != nil {
		http.Error(w, "La roadmap spécifiée n'existe pas", http.StatusNotFound)
		return
	}

	// Récupérer les jeux depuis le body
	var payload struct {
		roadmapsIds []string `json:"roadmapsIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Format du body invalide", http.StatusBadRequest)
		return
	}

	// Conversion en ObjectID
	var roadmapObjectIDs []primitive.ObjectID
	for _, idStr := range payload.roadmapsIds {
		roadmapID, err := primitive.ObjectIDFromHex(idStr)
		if err != nil {
			http.Error(w, fmt.Sprintf("ID de la roadmap invalide : %s", idStr), http.StatusBadRequest)
			return
		}
		roadmapObjectIDs = append(roadmapObjectIDs, roadmapID)
	}

	// Supprimer l'association côté `game`
	_, err = gameCollection.UpdateOne(ctx,
		bson.M{"_id": gameID},
		bson.M{"$pull": bson.M{"Roadmaps": bson.M{"$in": roadmapObjectIDs}}},
	)
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour du jeu", http.StatusInternalServerError)
		return
	}

	// Supprimer l'association côté `roadmap`
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	_, err = roadmapCollection.UpdateMany(ctx,
		bson.M{"_id": bson.M{"$in": roadmapObjectIDs}},
		bson.M{"$pull": bson.M{"Games": gameID}},
	)
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour des roadmaps", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"message":       "Roadmaps retirées du jeu avec succès",
		"removed_game":  gameID.Hex(),
		"removed_links": roadmapObjectIDs,
		"updated_by":    user.Email,
		"updated_at":    time.Now(),
	})
}

/* ---------- ROADMAPS  ---------- */

// Créer une roadmap (Superadmin uniquement)
func createSmashHereRoadmap(w http.ResponseWriter, r *http.Request) {
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
	if user.Type == nil || (*user.Type == "user") && (*user.Type != "superadmin") {
		http.Error(w, "Accès refusé : Vous n'avez pas les permissions pour créer une roadmap", http.StatusForbidden)
		return
	}

	// Lire les données multipart (image + champs)
	error := r.ParseMultipartForm(10 << 20)
	if error != nil {
		http.Error(w, "Erreur de parsing multipart", http.StatusBadRequest)
		return
	}

	// Champs texte
	title := r.FormValue("title")
	description := r.FormValue("description")
	subTitle := r.FormValue("subTitle")

	// Titre pas plus long que 30 caractères
	if len(title) > 120 {
		http.Error(w, "Le titre est trop long", http.StatusBadRequest)
		return
	}

	// Vérifie que le titre contient au moins une lettre
	matched, _ := regexp.MatchString(`[A-Za-z]`, title)
	if !matched {
		http.Error(w, "Le titre doit contenir au moins une lettre", http.StatusBadRequest)
		return
	}

	// Validation des champs obligatoires
	if title == "" || description == "" {
		http.Error(w, "Le titre et la description sont obligatoires", http.StatusBadRequest)
		return
	}

	// Traitement de l'image (champ `image`)
	file, fileHeader, err := r.FormFile("cover")
	if err != nil {
		http.Error(w, "Image de couverture manquante ou invalide", http.StatusBadRequest)
		return
	}
	defer file.Close()

	imageData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Erreur de lecture de l'image", http.StatusInternalServerError)
		return
	}

	// Nom du fichier S3
	ext := filepath.Ext(fileHeader.Filename)
	objectKey := fmt.Sprintf("roadmap/%s%s", title, ext)

	// Upload sur S3
	s3Uploader := database.BucketBasics{S3Client: database.S3Client}

	err = s3Uploader.UploadLargeObject(ctx, os.Getenv("AWS_S3_BUCKET_NAME"), objectKey, imageData)
	if err != nil {
		http.Error(w, "Erreur d'upload sur S3", http.StatusInternalServerError)
		return
	}

	// URL de l'image
	coverURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s",
		os.Getenv("AWS_S3_BUCKET_NAME"),
		os.Getenv("AWS_REGION"),
		objectKey,
	)

	// Initialisation des champs de la roadmap
	roadmapFields := models.Roadmap{
		ID:            primitive.NewObjectID(),
		CreatedBy:     user.ID,
		UpdatedBy:     user.ID,
		Title:         &title,
		Description:   &description,
		SubTitle:      &subTitle,
		Cover:         &coverURL,
		Published:     new(bool),
		Premium:       new(bool),
		ViewsPerDay:   new(int),
		ViewsPerWeek:  new(int),
		ViewsPerMonth: new(int),
		TotalViews:    new(int),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")

	// Vérifie que le titre de roadmap n'est pas déjà utilisé
	count, err := roadmapCollection.CountDocuments(ctx, bson.M{"title": title})
	if err != nil {
		http.Error(w, "Erreur lors de la vérification du titre", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Error(w, "Une roadmap avec ce nom existe déjà", http.StatusBadRequest)
		return
	}

	// Insérer la roadmap en base de données
	_, err = roadmapCollection.InsertOne(ctx, roadmapFields)
	if err != nil {
		http.Error(w, "Erreur lors de l'ajout de la roadmap", http.StatusInternalServerError)
		return
	}

	// Ajouter la roadmap à l'utilisateur
	userCollection := database.Client.Database("smashheredb").Collection("user")
	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{
		"$addToSet": bson.M{
			"RoadmapsCreated": roadmapFields.ID,
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

	// Vérifier l'utilisateur est connecté
	if user.ID.IsZero() {
		http.Error(w, "Accès refusé : Vous n'êtes pas connecté.", http.StatusForbidden)
		return
	}

	// Lire les données multipart (image + champs)
	error := r.ParseMultipartForm(10 << 20)
	if error != nil {
		http.Error(w, "Erreur de parsing multipart", http.StatusBadRequest)
		return
	}

	// Champs texte
	title := r.FormValue("title")
	description := r.FormValue("description")
	subTitle := r.FormValue("subTitle")

	// Titre pas plus long que 30 caractères
	if len(title) > 120 {
		http.Error(w, "Le titre est trop long", http.StatusBadRequest)
		return
	}

	// Vérifie que le titre contient au moins une lettre
	matched, _ := regexp.MatchString(`[A-Za-z]`, title)
	if !matched {
		http.Error(w, "Le titre doit contenir au moins une lettre", http.StatusBadRequest)
		return
	}

	// Validation des champs obligatoires
	if title == "" || description == "" || subTitle == "" {
		http.Error(w, "Le titre, sous-titre et la description sont obligatoires", http.StatusBadRequest)
		return
	}

	// Traitement de l'image (champ `image`)
	file, fileHeader, err := r.FormFile("cover")
	if err != nil {
		http.Error(w, "Image de couverture manquante ou invalide", http.StatusBadRequest)
		return
	}
	defer file.Close()

	imageData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Erreur de lecture de l'image", http.StatusInternalServerError)
		return
	}

	// Nom du fichier S3
	ext := filepath.Ext(fileHeader.Filename)
	objectKey := fmt.Sprintf("roadmap/%s%s", title, ext)

	// Upload sur S3
	s3Uploader := database.BucketBasics{S3Client: database.S3Client}

	err = s3Uploader.UploadLargeObject(ctx, os.Getenv("AWS_S3_BUCKET_NAME"), objectKey, imageData)
	if err != nil {
		http.Error(w, "Erreur d'upload sur S3", http.StatusInternalServerError)
		return
	}

	// URL de l'image
	coverURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s",
		os.Getenv("AWS_S3_BUCKET_NAME"),
		os.Getenv("AWS_REGION"),
		objectKey,
	)

	// Initialisation des champs de la roadmap
	roadmapFields := models.Roadmap{
		ID:            primitive.NewObjectID(),
		CreatedBy:     user.ID,
		UpdatedBy:     user.ID,
		Title:         &title,
		Description:   &description,
		SubTitle:      &subTitle,
		Cover:         &coverURL,
		Published:     new(bool),
		Premium:       new(bool),
		ViewsPerDay:   new(int),
		ViewsPerWeek:  new(int),
		ViewsPerMonth: new(int),
		TotalViews:    new(int),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")

	// Vérifie que le titre de roadmap n'est pas déjà utilisé
	count, err := roadmapCollection.CountDocuments(ctx, bson.M{"title": title})
	if err != nil {
		http.Error(w, "Erreur lors de la vérification du titre", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Error(w, "Une roadmap avec ce nom existe déjà", http.StatusBadRequest)
		return
	}

	// Insérer la roadmap en base de données
	_, err = roadmapCollection.InsertOne(ctx, roadmapFields)
	if err != nil {
		http.Error(w, "Erreur lors de l'ajout de la roadmap", http.StatusInternalServerError)
		return
	}

	// Ajouter la roadmap à l'utilisateur
	userCollection := database.Client.Database("smashheredb").Collection("user")
	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{
		"$addToSet": bson.M{
			"RoadmapsCreated": roadmapFields.ID,
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
	if user.ID.IsZero() {
		http.Error(w, "Accès refusé : Vous devez être connecté.", http.StatusForbidden)
		return
	}

	// Extraire l’ID de roadmap depuis l’URL
	pathParts := strings.Split(r.URL.Path, "/")

	if len(pathParts) < 4 || pathParts[3] != "games" {
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

// Récupérer les étapes d'une roadmap dans l'ordre
func getRoadmapSteps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Récupération de l'ID de la roadmap
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 4 || pathParts[1] != "roadmap" {
		log.Println(pathParts)
		http.Error(w, "URL invalide", http.StatusBadRequest)
		return
	}
	roadmapIDStr := pathParts[2]
	roadmapID, err := primitive.ObjectIDFromHex(roadmapIDStr)
	if err != nil {
		http.Error(w, "ID de la roadmap invalide", http.StatusBadRequest)
		return
	}

	// roadmapIDStr := strings.TrimPrefix(r.URL.Path, "/roadmap/")
	// roadmapIDStr = strings.TrimSuffix(roadmapIDStr, "/steps") // retire le suffixe pour extraire l'ID
	// roadmapID, err := primitive.ObjectIDFromHex(roadmapIDStr)
	// if err != nil {
	// 	http.Error(w, "ID de roadmap invalide", http.StatusBadRequest)
	// 	return
	// }

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Récupérer la roadmap
	var roadmap models.Roadmap
	err = database.Client.Database("smashheredb").Collection("roadmap").FindOne(ctx, bson.M{"_id": roadmapID}).Decode(&roadmap)
	if err != nil {
		http.Error(w, "Roadmap non trouvée", http.StatusNotFound)
		return
	}

	// Si aucune étape définie
	if roadmap.Steps == nil || len(roadmap.Steps) == 0 {
		json.NewEncoder(w).Encode([]any{})
		return
	}

	// Récupérer les étapes une par une en respectant l’ordre
	stepCollection := database.Client.Database("smashheredb").Collection("step")
	cursor, err := stepCollection.Find(ctx, bson.M{"_id": bson.M{"$in": roadmap.Steps}})
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des etapes", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var steps []models.Step
	if err := cursor.All(ctx, &steps); err != nil {
		http.Error(w, "Erreur lors du parsing des données", http.StatusInternalServerError)
		return
	}
	// var orderedSteps []models.Step

	// for stepID := range roadmap.Steps {
	// 	var step models.Step
	// 	err := stepCollection.FindOne(ctx, bson.M{"_id": stepID}).Decode(&step)
	// 	if err == nil {
	// 		orderedSteps = append(orderedSteps, step)
	// 	}
	// }

	json.NewEncoder(w).Encode(steps)
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
	if user.Type == nil || (*user.Type == "user") {
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

// Récupérer toutes les roadmaps publiées
func getAllPublishedRoadmaps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
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

// Récupérer les commentaires d'une roadmap
func getRoadmapComments(w http.ResponseWriter, r *http.Request) {
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
	if len(tokenString) > 7 && strings.HasPrefix(tokenString, "Bearer ") {
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

	if user.ID.IsZero() {
		http.Error(w, "Utilisateur invalide", http.StatusForbidden)
		return
	}

	// Extraire l'ID de la roadmap depuis l'URL
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
	var roadmap models.Roadmap
	err = database.Client.Database("smashheredb").Collection("roadmap").FindOne(ctx, bson.M{"_id": roadmapID}).Decode(&roadmap)
	if err != nil {
		http.Error(w, "Roadmap introuvable", http.StatusNotFound)
		return
	}

	// Lire les paramètres de pagination
	limit := int64(10)
	skip := int64(0)
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.ParseInt(l, 10, 64); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if s := r.URL.Query().Get("skip"); s != "" {
		if parsed, err := strconv.ParseInt(s, 10, 64); err == nil && parsed >= 0 {
			skip = parsed
		}
	}

	// Compter les commentaires de cette roadmap
	commentCollection := database.Client.Database("smashheredb").Collection("comment")
	totalCount, err := commentCollection.CountDocuments(ctx, bson.M{"Roadmap": roadmapID})
	if err != nil {
		http.Error(w, "Erreur lors du comptage des commentaires", http.StatusInternalServerError)
		return
	}

	// Récupérer les commentaires
	cursor, err := commentCollection.Find(ctx,
		bson.M{"Roadmap": roadmapID},
		options.Find().
			SetSort(bson.D{{Key: "createdAt", Value: -1}}).
			SetLimit(limit).
			SetSkip(skip),
	)
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des commentaires", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var comments []models.Comment
	if err := cursor.All(ctx, &comments); err != nil {
		http.Error(w, "Erreur lors du parsing des données", http.StatusInternalServerError)
		return
	}

	hasMore := (skip + limit) < totalCount

	json.NewEncoder(w).Encode(map[string]any{
		"comments":   comments,
		"totalCount": totalCount,
		"limit":      limit,
		"skip":       skip,
		"hasMore":    hasMore,
	})
}

// Supprimer une roadmap
func deleteOneRoadmap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

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
	if user.ID.IsZero() {
		http.Error(w, "Accès refusé, vous devez être connecté", http.StatusForbidden)
		return
	}

	// ID roadmap
	roadmapIdStr := strings.TrimPrefix(r.URL.Path, "/roadmap/")
	roadmapID, err := primitive.ObjectIDFromHex(roadmapIdStr)
	if err != nil {
		http.Error(w, "ID de roadmap invalide", http.StatusBadRequest)
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

	/*  Suppression des commentaires de la roadmap
	commentCollection := database.Client.Database("smashheredb").Collection("comment")

	// Étape 1 : récupérer les commentaires associés à la roadmap
	cursor, err := commentCollection.Find(ctx, bson.M{"Roadmap": roadmapID})
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des commentaires", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var comments []models.Comment
	if err := cursor.All(ctx, &comments); err != nil {
		http.Error(w, "Erreur lors du parsing des commentaires", http.StatusInternalServerError)
		return
	}

	var commentIDs []primitive.ObjectID
	for _, c := range comments {
		commentIDs = append(commentIDs, c.ID)
	}

	// Étape 2 : suppression des commentaires dans les utilisateurs
	_, err = userCollection.UpdateMany(ctx,
		bson.M{"Comments": bson.M{"$in": commentIDs}},
		bson.M{"$pull": bson.M{"Comments": bson.M{"$in": commentIDs}}},
	)
	if err != nil {
		http.Error(w, "Erreur lors du nettoyage des commentaires dans les utilisateurs", http.StatusInternalServerError)
		return
	}

	// Étape 3 : suppression des commentaires dans la collection comment
	_, err = commentCollection.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": commentIDs}})
	if err != nil {
		http.Error(w, "Erreur lors de la suppression des commentaires", http.StatusInternalServerError)
		return
	}
	*/

	// Suppression de la roadmap
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	result, err := roadmapCollection.DeleteOne(ctx, bson.M{"_id": roadmapID})
	if err != nil {
		http.Error(w, "Erreur lors de la suppression de la roadmap", http.StatusInternalServerError)
		return
	}

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

	// Lire les données multipart (image + champs)
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Erreur de parsing multipart", http.StatusBadRequest)
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

	if user.ID.IsZero() {
		http.Error(w, "Accès refusé, vous devez être connecté", http.StatusForbidden)
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
	title := r.FormValue("title")
	description := r.FormValue("description")
	subTitle := r.FormValue("subTitle")
	publishedStr := r.FormValue("published")
	premiumStr := r.FormValue("premium")
	Steps := r.FormValue("Steps")
	Games := r.FormValue("Games")
	Tags := r.FormValue("Tags")

	// Construction du $set dynamique
	updateFields := bson.M{}

	// Traitement de l'image (champ `image`)
	file, fileHeader, err := r.FormFile("cover")
	if err == nil {
		defer file.Close()
		imageData, _ := io.ReadAll(file)
		ext := filepath.Ext(fileHeader.Filename)
		safeTitle := title
		if safeTitle == "" {
			safeTitle = "cover"
		}
		objectKey := fmt.Sprintf("roadmap/%s%s", *updatedRoadmap.Title, ext)

		s3Uploader := database.BucketBasics{S3Client: database.S3Client}
		err = s3Uploader.UploadLargeObject(ctx, os.Getenv("AWS_S3_BUCKET_NAME"), objectKey, imageData)
		if err == nil {
			coverURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s",
				os.Getenv("AWS_S3_BUCKET_NAME"),
				os.Getenv("AWS_REGION"),
				objectKey,
			)
			updateFields["cover"] = coverURL
		}
	}

	if title != "" {
		updateFields["title"] = title
	}
	if description != "" {
		updateFields["description"] = description
	}
	if subTitle != "" {
		updateFields["subTitle"] = subTitle
	}
	if publishedStr != "" {
		pub, err := strconv.ParseBool(publishedStr)
		if err != nil {
			http.Error(w, "Valeur de published invalide", http.StatusBadRequest)
			return
		}
		updateFields["published"] = pub
	}
	if premiumStr != "" {
		pr, err := strconv.ParseBool(premiumStr)
		if err != nil {
			http.Error(w, "Valeur de premium invalide", http.StatusBadRequest)
			return
		}
		updateFields["premium"] = pr
	}
	if Games != "" {
		gameIDs, err := parseObjectIDArray(Games)
		if err != nil {
			http.Error(w, "Liste de jeux invalide", http.StatusBadRequest)
			return
		}
		updateFields["Games"] = gameIDs
	}
	if Steps != "" {
		stepIDs, err := parseObjectIDArray(Steps)
		if err != nil {
			http.Error(w, "Liste d'étapes invalide", http.StatusBadRequest)
			return
		}
		updateFields["Steps"] = stepIDs
	}
	if Tags != "" {
		tagIDs, err := parseObjectIDArray(Tags)
		if err != nil {
			http.Error(w, "Liste de tags invalide", http.StatusBadRequest)
			return
		}
		updateFields["Tags"] = tagIDs
	}

	updateFields["UpdatedAt"] = time.Now()
	updateFields["UpdatedBy"] = user.ID

	// Si aucun champ modifié
	if len(updateFields) == 0 {
		http.Error(w, "Aucun champ valide à modifier", http.StatusBadRequest)
		return
	}

	filter := bson.M{"_id": roadmapID}
	update := bson.M{"$set": updateFields}
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
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

// Modifier les informations d'une roadmap
func updateRoadmapInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Lire les données multipart (image + champs)
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Erreur de parsing multipart", http.StatusBadRequest)
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

	if user.ID.IsZero() {
		http.Error(w, "Accès refusé, vous devez être connecté", http.StatusForbidden)
		return
	}

	// Récupérer l'ID de la roadmap
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 4 {
		http.Error(w, "URL invalide", http.StatusBadRequest)
		return
	}
	roadmapIDStr := pathParts[2] // L'ID est en position 2 dans "/roadmap/{id}/info"
	roadmapID, err := primitive.ObjectIDFromHex(roadmapIDStr)
	if err != nil {
		http.Error(w, "ID de roadmap invalide", http.StatusBadRequest)
		return
	}

	// Body à mettre à jour
	// var updatedRoadmap models.Roadmap
	title := r.FormValue("title")
	description := r.FormValue("description")
	subTitle := r.FormValue("subTitle")
	publishedStr := r.FormValue("published")
	premiumStr := r.FormValue("premium")
	Games := r.FormValue("Games")

	// Construction du $set dynamique
	updateFields := bson.M{}

	// Traitement de l'image (champ `image`)
	file, fileHeader, err := r.FormFile("cover")
	if err == nil {
		defer file.Close()
		imageData, _ := io.ReadAll(file)
		ext := filepath.Ext(fileHeader.Filename)
		safeTitle := title
		if safeTitle == "" {
			safeTitle = "cover"
		}
		cleanTitle := strings.ReplaceAll(title, " ", "_")
		cleanTitle = strings.ReplaceAll(cleanTitle, "/", "_")
		cleanTitle = strings.ReplaceAll(cleanTitle, "\\", "_")
		timestamp := time.Now().Unix()
		objectKey := fmt.Sprintf("roadmap/%s_%d%s", cleanTitle, timestamp, ext)

		s3Uploader := database.BucketBasics{S3Client: database.S3Client}
		err = s3Uploader.UploadLargeObject(ctx, os.Getenv("AWS_S3_BUCKET_NAME"), objectKey, imageData)
		if err == nil {
			coverURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s",
				os.Getenv("AWS_S3_BUCKET_NAME"),
				os.Getenv("AWS_REGION"),
				objectKey,
			)
			updateFields["cover"] = coverURL
		}
	}

	if title != "" {
		updateFields["title"] = title
	}
	if description != "" {
		updateFields["description"] = description
	}
	if subTitle != "" {
		updateFields["subTitle"] = subTitle
	}
	if publishedStr != "" {
		pub, err := strconv.ParseBool(publishedStr)
		if err != nil {
			http.Error(w, "Valeur de published invalide", http.StatusBadRequest)
			return
		}
		updateFields["published"] = pub
	}
	if premiumStr != "" {
		pr, err := strconv.ParseBool(premiumStr)
		if err != nil {
			http.Error(w, "Valeur de premium invalide", http.StatusBadRequest)
			return
		}
		updateFields["premium"] = pr
	}
	if Games != "" {
		gameIDs, err := parseObjectIDArray(Games)
		if err != nil {
			http.Error(w, "Liste de jeux invalide", http.StatusBadRequest)
			return
		}
		updateFields["Games"] = gameIDs
	}

	updateFields["UpdatedAt"] = time.Now()
	updateFields["UpdatedBy"] = user.ID

	// Si aucun champ modifié
	if len(updateFields) == 0 {
		http.Error(w, "Aucun champ valide à modifier", http.StatusBadRequest)
		return
	}

	filter := bson.M{"_id": roadmapID}
	update := bson.M{"$set": updateFields}
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
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

// Modifier les étapes d'une roadmap
func updateRoadmapSteps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Lire les données multipart (image + champs)
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Erreur de parsing multipart", http.StatusBadRequest)
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

	if user.ID.IsZero() {
		http.Error(w, "Accès refusé, vous devez être connecté", http.StatusForbidden)
		return
	}

	// Vérif méthode POST ou PUT
	r.ParseForm()
	pathParts := strings.Split(r.URL.Path, "/")

	if len(pathParts) < 4 || pathParts[1] != "roadmap" || pathParts[3] != "steps" {
		http.Error(w, "URL invalide", http.StatusBadRequest)
		return
	}

	roadmapIDStr := pathParts[2]
	roadmapID, _ := primitive.ObjectIDFromHex(roadmapIDStr)
	stepIDsStr := r.FormValue("Steps")

	objIDs := []primitive.ObjectID{}
	if stepIDsStr != "" {
		for _, sid := range strings.Split(stepIDsStr, ",") {
			sid = strings.TrimSpace(sid) // Supprimer les espaces
			if sid != "" {               // Vérifier que l'ID n'est pas vide
				oid, err := primitive.ObjectIDFromHex(sid)
				if err != nil {
					http.Error(w, fmt.Sprintf("ID d'étape invalide: %s", sid), http.StatusBadRequest)
					return
				}
				objIDs = append(objIDs, oid)
			}
		}
	}

	_, err = database.Client.Database("smashheredb").Collection("roadmap").UpdateOne(context.Background(), bson.M{"_id": roadmapID},
		bson.M{"$set": bson.M{"Steps": objIDs}},
	)
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour", http.StatusInternalServerError)
	}
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(map[string]any{
		"message":    "Étapes de la roadmap modifiées avec succès",
		"updated_at": time.Now(),
		"RoadmapID":  roadmapID,
		"Steps":      objIDs,
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

// Supprimer une étape d'une roadmap
func removeStepFromRoadmap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Authentification
	token := r.Header.Get("Authorization")
	if token == "" || len(token) < 8 || !strings.HasPrefix(token, "Bearer ") {
		http.Error(w, "Token manquant ou invalide", http.StatusUnauthorized)
		return
	}
	email, err := extractEmailFromToken(token[7:])
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

	// Récupérer roadmapId et stepId
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "URL invalide", http.StatusBadRequest)
		return
	}
	roadmapID, err := primitive.ObjectIDFromHex(parts[2])
	stepID, err2 := primitive.ObjectIDFromHex(parts[4])
	if err != nil || err2 != nil {
		http.Error(w, "ID invalide", http.StatusBadRequest)
		return
	}

	stepCollection := database.Client.Database("smashheredb").Collection("step")

	// Supprimer les références à cette étape dans PreviousSteps et NextSteps d'autres étapes
	_, err = stepCollection.UpdateMany(ctx, bson.M{
		"PreviousSteps": stepID,
	}, bson.M{
		"$pull": bson.M{"PreviousSteps": stepID},
	})
	if err != nil {
		http.Error(w, "Erreur lors du nettoyage des PreviousSteps", http.StatusInternalServerError)
		return
	}

	_, err = stepCollection.UpdateMany(ctx, bson.M{
		"NextSteps": stepID,
	}, bson.M{
		"$pull": bson.M{"NextSteps": stepID},
	})
	if err != nil {
		http.Error(w, "Erreur lors du nettoyage des NextSteps", http.StatusInternalServerError)
		return
	}

	// Mise à jour de la roadmap (retrait de l'étape)
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	update := bson.M{
		"$pull": bson.M{"Steps": stepID},
		"$set":  bson.M{"UpdatedAt": time.Now()},
	}
	result, err := roadmapCollection.UpdateOne(ctx, bson.M{"_id": roadmapID}, update)
	if err != nil {
		http.Error(w, "Erreur lors de la suppression de l'étape", http.StatusInternalServerError)
		return
	}
	if result.MatchedCount == 0 {
		http.Error(w, "Roadmap non trouvée", http.StatusNotFound)
		return
	}

	// Supprimer cette étape des contenus (champ Steps)
	contentCollection := database.Client.Database("smashheredb").Collection("content")
	_, err = contentCollection.UpdateMany(ctx, bson.M{
		"Steps": stepID,
	}, bson.M{
		"$pull": bson.M{"Steps": stepID},
	})
	if err != nil {
		http.Error(w, "Erreur lors du nettoyage des contenus", http.StatusInternalServerError)
		return
	}

	// Réponse
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"message": "Étape retirée avec succès de la roadmap",
		"step_id": stepID.Hex(),
	})
}

// Publier ou dépublier une roadmap
func publishRoadmap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
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

	var updatedRoadmap models.Roadmap

	err = json.NewDecoder(r.Body).Decode(&updatedRoadmap)
	if err != nil {
		http.Error(w, "Format de données invalide", http.StatusBadRequest)
		return
	}

	updateFields := bson.M{}
	if updatedRoadmap.Published != nil {
		updateFields["published"] = updatedRoadmap.Published
	}
	updateFields["UpdatedAt"] = time.Now()
	updateFields["UpdatedBy"] = user.ID

	// Si aucun champ modifié
	if len(updateFields) == 0 {
		http.Error(w, "Aucun champ valide à modifier", http.StatusBadRequest)
		return
	}

	filter := bson.M{"_id": roadmapID}
	update := bson.M{"$set": updateFields}
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
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

// Définir une roadmap comme premium ou non
func setRoadmapPremium(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
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

	// Récupération de l'utilisateur
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
	roadmapIDStr := strings.TrimPrefix(r.URL.Path, "/roadmap/")
	roadmapID, err := primitive.ObjectIDFromHex(roadmapIDStr)
	if err != nil {
		http.Error(w, "ID de roadmap invalide", http.StatusBadRequest)
		return
	}

	// Lecture du corps JSON
	var updatedRoadmap models.Roadmap
	if err := json.NewDecoder(r.Body).Decode(&updatedRoadmap); err != nil {
		http.Error(w, "Format de données invalide", http.StatusBadRequest)
		return
	}

	// Préparer les champs à modifier
	updateFields := bson.M{}
	if updatedRoadmap.Premium != nil {
		updateFields["premium"] = updatedRoadmap.Premium
	}
	updateFields["UpdatedAt"] = time.Now()
	updateFields["UpdatedBy"] = user.ID

	if len(updateFields) == 0 {
		http.Error(w, "Aucun champ à modifier", http.StatusBadRequest)
		return
	}

	// Mise à jour MongoDB
	roadmapCollection := database.Client.Database("smashheredb").Collection("roadmap")
	result, err := roadmapCollection.UpdateOne(ctx, bson.M{"_id": roadmapID}, bson.M{"$set": updateFields})
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour", http.StatusInternalServerError)
		return
	}
	if result.MatchedCount == 0 {
		http.Error(w, "Aucune roadmap trouvée", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"message":    "Champ premium mis à jour avec succès",
		"updated_at": time.Now(),
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
	if user.ID.IsZero() {
		http.Error(w, "Accès refusé : Vous n'êtes pas connecté.", http.StatusForbidden)
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

	// Insérer dans l'utilisateur
	userCollection := database.Client.Database("smashheredb").Collection("user")
	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{
		"$addToSet": bson.M{
			"StepsCreated": step.ID,
		},
		"$set": bson.M{
			"UpdatedAt": time.Now(),
			"UpdatedBy": user.ID,
		},
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Erreur lors de la mise à jour de l'utilisateur : %s", step.ID.Hex()), http.StatusInternalServerError)
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
	if user.Type == nil || (*user.Type == "user") {
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
		updateFields["subTitle"] = updatedStep.Subtitle
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
		fmt.Println(err, updateFields)
		http.Error(w, "Aucune étape trouvée", http.StatusNotFound)
		return
	}

	// Synchroniser les relations inverses (PreviousSteps <=> NextSteps)
	if updatedStep.PreviousSteps != nil {
		for _, prevID := range updatedStep.PreviousSteps {
			_, _ = stepCollection.UpdateOne(ctx, bson.M{"_id": prevID}, bson.M{
				"$addToSet": bson.M{"NextSteps": stepID},
			})
		}
	}
	if updatedStep.NextSteps != nil {
		for _, nextID := range updatedStep.NextSteps {
			_, _ = stepCollection.UpdateOne(ctx, bson.M{"_id": nextID}, bson.M{
				"$addToSet": bson.M{"PreviousSteps": stepID},
			})
		}
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
	if user.ID.IsZero() {
		http.Error(w, "Accès refusé : Vous n'êtes pas connecté.", http.StatusForbidden)
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

	// Supprimer le contenu de l'utilisateur
	userCollection := database.Client.Database("smashheredb").Collection("user")
	userCollection.UpdateOne(
		ctx,
		bson.M{"StepsCreated": stepID},
		bson.M{"$pull": bson.M{"StepsCreated": stepID}},
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

// Récupérer la liste des contenus d'une roadmap
func getContentsFromStep(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Extraire l’ID du jeu depuis l’URL
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 4 || pathParts[1] != "step" {
		log.Println(pathParts)
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

	// Récupérer les contenus
	contentCollection := database.Client.Database("smashheredb").Collection("content")
	cursor, err := contentCollection.Find(ctx, bson.M{"_id": bson.M{"$in": step.Contents}})
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
	if user.ID.IsZero() {
		http.Error(w, "Accès refusé : Vous n'êtes pas connecté.", http.StatusForbidden)
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

	// Insérer dans l'utilisateur
	userCollection := database.Client.Database("smashheredb").Collection("user")
	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{
		"$addToSet": bson.M{
			"ContentsCreated": content.ID,
		},
		"$set": bson.M{
			"UpdatedAt": time.Now(),
			"UpdatedBy": user.ID,
		},
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Erreur lors de la mise à jour de l'utilisateur : %s", content.ID.Hex()), http.StatusInternalServerError)
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

	if user.ID.IsZero() {
		http.Error(w, "Utilisateur invalide", http.StatusForbidden)
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

	// Supprimer le contenu de l'utilisateur
	userCollection := database.Client.Database("smashheredb").Collection("user")
	userCollection.UpdateOne(
		ctx,
		bson.M{"ContentsCreated": contentID},
		bson.M{"$pull": bson.M{"ContentsCreated": contentID}},
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
	if user.Type == nil || (*user.Type == "user") {
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
	if user.Type == nil || (*user.Type == "user") {
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
	if user.Type == nil || (*user.Type == "user") {
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

	if user.Type == nil || (*user.Type == "user") {
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
