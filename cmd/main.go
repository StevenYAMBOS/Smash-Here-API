package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/StevenYAMBOS/Smash-Here-API/database"
	"github.com/StevenYAMBOS/Smash-Here-API/routes"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
)

func main() {

	err := godotenv.Load(".env")
	// En Go, nil signifie "aucune erreur"
	if err != nil {
		log.Fatalf("Erreur lors du chargement des variables d'environnement: %s", err)
	}

	database.InitDatabase()
	database.InitS3Client()
	PORT := os.Getenv("PORT")
	router := routes.Router()
	handler := cors.Default().Handler(router)

	fmt.Println("Application lancée : http://localhost" + PORT)
	http.ListenAndServe(PORT, handler)
}
