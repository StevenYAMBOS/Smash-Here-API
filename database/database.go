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

func InitDatabase() {
	err := godotenv.Load(".env") // va charger les variables d'environnement dans le fichier '.env'
	if err != nil {
		log.Fatalf("Erreur lors du chargement des variables d'environnement: %s", err)
	}

	DATABASE_URL := os.Getenv("DATABASE_URL") // va récupérer la variable d'environnement dans le fichier '.env'

	// Connection à la base de données
	clientOption := options.Client().ApplyURI(DATABASE_URL)
	client, err := mongo.Connect(context.Background(), clientOption)
	if err != nil {
		log.Fatal(err)
	}

	// Vérifier la connection
	/* La méthode 'Ping()' permet de vérifier si une BDD MongoDB a été trouvée */
	if err := client.Ping(context.TODO(), readpref.Primary()); err != nil {
		panic(err)
	}

	fmt.Println(`Connexion à la base de données réussie !`)
}
