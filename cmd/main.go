package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

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
	if !strings.HasPrefix(PORT, ":") {
		PORT = ":" + PORT
	}
	router := routes.Router()
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:5173"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	})

	handler := c.Handler(router)

	fmt.Println("Application lancée : http://localhost" + PORT)
	http.ListenAndServe(PORT, handler)
}
