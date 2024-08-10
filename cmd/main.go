package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/StevenYAMBOS/Smash-Here-API/api/database"
	"github.com/StevenYAMBOS/Smash-Here-API/internal/routes"
	"github.com/joho/godotenv"
)

func main() {
	// Variables d'environnement
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Erreur lors du chargement des variables d'environnement: %s", err)
	}

	// Port
	PORT := os.Getenv("PORT")

	// Route principale de l'application
	router := routes.Router()

	fmt.Println("Application lancée : http://localhost" + PORT)

	// Lancement de la base de données
	database.InitDatabase()

	// Lancement de l'application
	if err := http.ListenAndServe(":"+PORT, router); err != nil {
		fmt.Println("Erreur serveur : ", err)
	}
}
