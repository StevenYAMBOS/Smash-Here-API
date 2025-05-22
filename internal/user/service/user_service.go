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
