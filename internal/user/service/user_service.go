/*
internal/user/service/user_service.go
*/

package service

import (
	"context"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"path/filepath"
	"regexp"
	"time"

	"github.com/StevenYAMBOS/Smash-Here-API/database"
	"github.com/StevenYAMBOS/Smash-Here-API/models"
	"github.com/StevenYAMBOS/Smash-Here-API/pkg/auth"
	"github.com/StevenYAMBOS/Smash-Here-API/pkg/config"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// UserService orchestre les cas d’usage liés aux utilisateurs.
type UserService struct {
	bucketName string
	region     string
	dbName     string
}

// NewUserService instancie le service avec la config S3.
func NewUserService() *UserService {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Erreur de config : %v", err)
	}
	return &UserService{
		bucketName: cfg.AWSS3BucketName,
		region:     cfg.AWSS3Region,
		dbName:     cfg.DBName,
	}
}

// Inscription
func (s *UserService) Register(
	ctx context.Context,
	username, email, password string,
	file multipart.File,
	fileHeader *multipart.FileHeader,
) (*models.User, error) {
	// 1. validations
	if username == "" || email == "" || password == "" {
		return nil, fmt.Errorf("tous les champs sont obligatoires")
	}
	if len(username) > 30 {
		return nil, fmt.Errorf("le pseudo est trop long")
	}
	if ok, _ := regexp.MatchString(`[A-Za-z]`, username); !ok {
		return nil, fmt.Errorf("le pseudo doit contenir une lettre")
	}
	if len(password) < 6 {
		return nil, fmt.Errorf("le mot de passe doit contenir au moins 6 caractères")
	}

	// 2. lecture et upload de l’image
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	ext := filepath.Ext(fileHeader.Filename)
	key := fmt.Sprintf("user/%s%s", username, ext)
	uploader := database.BucketBasics{S3Client: database.S3Client}
	if err := uploader.UploadLargeObject(ctx, s.bucketName, key, data); err != nil {
		return nil, err
	}
	imageURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", s.bucketName, s.region, key)

	// 3. hash du mot de passe et création de l’entité
	hashed := auth.HashPassword(password)
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

	// 4. insertion Mongo + unicité pseudo
	coll := database.Client.Database("smashheredb").Collection("user")
	if count, err := coll.CountDocuments(ctx, bson.M{"username": username}); err != nil {
		return nil, err
	} else if count > 0 {
		return nil, fmt.Errorf("pseudo déjà utilisé")
	}
	if _, err := coll.InsertOne(ctx, user); err != nil {
		return nil, err
	}

	return &user, nil
}

// Connexion
func (s *UserService) Login(ctx context.Context, email, password string) (string, error) {
	coll := database.Client.Database("smashheredb").Collection("user")
	var stored models.User
	if err := coll.FindOne(ctx, bson.M{"email": email}).Decode(&stored); err != nil {
		return "", fmt.Errorf("email ou mot de passe incorrect")
	}
	if !auth.CheckPasswordHash(password, *stored.Password) {
		return "", fmt.Errorf("email ou mot de passe incorrect")
	}
	token, err := auth.CreateToken(stored.Email)
	if err != nil {
		return "", err
	}
	// mise à jour lastLogin (silent)
	coll.UpdateOne(ctx, bson.M{"email": stored.Email}, bson.M{"$set": bson.M{"lastLogin": time.Now()}})
	return token, nil
}

// Récupérer les informations de l'utilisateur connecté
func (s *UserService) GetProfile(ctx context.Context, email string) (*models.User, error) {
	coll := database.Client.Database("smashheredb").Collection("user")
	var user models.User
	if err := coll.FindOne(ctx, bson.M{"email": email}).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

// Renvoie la liste des roadmaps créées par l'utilisateur.
func (s *UserService) GetUserRoadmaps(ctx context.Context, email string) ([]models.Roadmap, error) {
	// 1. Récupérer l'utilisateur
	userColl := database.Client.Database(s.dbName).Collection("user")
	var u models.User
	if err := userColl.FindOne(ctx, bson.M{"email": email}).Decode(&u); err != nil {
		return nil, fmt.Errorf("utilisateur non trouvé : %w", err)
	}

	// 2. Récupérer les roadmaps
	roadmapColl := database.Client.Database(s.dbName).Collection("roadmap")
	cursor, err := roadmapColl.Find(ctx, bson.M{"_id": bson.M{"$in": u.RoadmapsCreated}})
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la récupération des roadmaps : %w", err)
	}
	defer cursor.Close(ctx)

	var roadmaps []models.Roadmap
	if err := cursor.All(ctx, &roadmaps); err != nil {
		return nil, fmt.Errorf("erreur de parsing des données : %w", err)
	}
	return roadmaps, nil
}

// Met à jour le profil d'un utilisateur
func (s *UserService) UpdateProfile(
	ctx context.Context,
	email, newUsername string,
	file multipart.File, header *multipart.FileHeader,
) (*models.User, error) {
	// récupérer l'utilisateur
	coll := database.Client.Database(s.dbName).Collection("user")
	var user models.User
	if err := coll.FindOne(ctx, bson.M{"email": email}).Decode(&user); err != nil {
		return nil, fmt.Errorf("utilisateur non trouvé")
	}

	update := bson.M{"UpdatedAt": time.Now(), "UpdatedBy": user.ID}
	// pseudo
	if newUsername != "" && newUsername != *user.Username {
		if len(newUsername) > 30 {
			return nil, fmt.Errorf("le pseudo est trop long (max 30 caractères)")
		}
		if ok, _ := regexp.MatchString(`[A-Za-z]`, newUsername); !ok {
			return nil, fmt.Errorf("le pseudo doit contenir au moins une lettre")
		}
		count, err := coll.CountDocuments(ctx, bson.M{"username": newUsername})
		if err != nil {
			return nil, fmt.Errorf("erreur vérification pseudo")
		}
		if count > 0 {
			return nil, fmt.Errorf("pseudo déjà utilisé")
		}
		update["username"] = newUsername
	}

	// image
	if file != nil && header != nil {
		data, err := io.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("lecture image impossible")
		}
		ext := filepath.Ext(header.Filename)
		key := fmt.Sprintf("user/%s%s", *user.Username, ext)
		uploader := database.BucketBasics{S3Client: database.S3Client}
		if err := uploader.UploadLargeObject(ctx, s.bucketName, key, data); err != nil {
			return nil, fmt.Errorf("upload S3 échoué : %w", err)
		}
		url := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", s.bucketName, s.region, key)
		update["profilePicture"] = url
	}

	res, err := coll.UpdateOne(ctx,
		bson.M{"_id": user.ID},
		bson.M{"$set": update},
	)
	if err != nil {
		return nil, fmt.Errorf("erreur update en base")
	}
	if res.MatchedCount == 0 {
		return nil, fmt.Errorf("aucun utilisateur modifié")
	}

	if err := coll.FindOne(ctx, bson.M{"_id": user.ID}).Decode(&user); err != nil {
		return nil, fmt.Errorf("lecture post-update échouée")
	}
	return &user, nil
}

// Récupérer les informations d'un utilisateur
func (s *UserService) GetUserByID(ctx context.Context, currentEmail string, targetID primitive.ObjectID) (*models.User, error) {
	coll := database.Client.Database(s.dbName).Collection("user")

	// Récupérer l'utilisateur courant et vérifier son rôle
	var current models.User
	if err := coll.FindOne(ctx, bson.M{"email": currentEmail}).Decode(&current); err != nil {
		return nil, fmt.Errorf("accès refusé")
	}
	if current.Type == nil || (*current.Type != "coach" && *current.Type != "superadmin") {
		return nil, fmt.Errorf("accès refusé")
	}

	// Récupérer l'utilisateur ciblé
	var target models.User
	if err := coll.FindOne(ctx, bson.M{"_id": targetID}).Decode(&target); err != nil {
		return nil, fmt.Errorf("utilisateur non trouvé")
	}

	// Masquer le mot de passe
	target.Password = nil
	return &target, nil
}
