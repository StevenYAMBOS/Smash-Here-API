package database

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var Client *mongo.Client

// Initialiser la base de données
func InitDatabase() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Erreur lors du chargement des variables d'environnement: %s", err)
	}

	DATABASE_URL := os.Getenv("DATABASE_URL")
	if DATABASE_URL == "" {
		log.Fatalf("DATABASE_URL n'est pas défini dans le fichier .env")
	}

	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(DATABASE_URL))
	if err != nil {
		log.Fatalf("Erreur de connexion à MongoDB: %s", err)
	}

	Client = client
	fmt.Println("Connexion à la base de données réussie !")
}
