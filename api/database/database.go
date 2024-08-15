// api/database/database.go

package database

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

var Client *mongo.Client

func InitDatabase() {
	err := godotenv.Load(".env") // va charger les variables d'environnement dans le fichier '.env'
	if err != nil {
		log.Fatalf("Erreur lors du chargement des variables d'environnement: %s", err)
	}

	DATABASE_URL := os.Getenv("DATABASE_URL")
	if DATABASE_URL == "" {
		log.Fatalf("DATABASE_URL n'est pas défini dans le fichier .env")
	}

	// Connection à la base de données
	clientOption := options.Client().ApplyURI("mongodb://localhost:27017")
	Client, err := mongo.Connect(context.Background(), clientOption)
	if err != nil {
		log.Fatal(err)
	}

	// Vérifier la connection
	/* La méthode 'Ping()' permet de vérifier si une BDD MongoDB a été trouvée */
	if err := Client.Ping(context.TODO(), readpref.Primary()); err != nil {
		log.Fatal("Impossible de pinger MongoDB : ", err)
	}


	if Client == nil {
		log.Fatal("Le client MongoDB n'a pas été initialisé après la connexion.")
	}

	fmt.Println(`Connexion à la base de données réussie !`)
}

func GetCollection(collectionName string) *mongo.Collection {
	if Client == nil {
		log.Fatal("MongoDB client n'est pas initialisé.")
	}
	return Client.Database("smash_here_db").Collection(collectionName)
}
