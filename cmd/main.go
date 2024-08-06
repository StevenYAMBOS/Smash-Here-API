package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/StevenYAMBOS/main/database"
	"github.com/joho/godotenv"
	// "github.com/StevenYAMBOS/main/routes"
)

func main() {
	// Variables d'environnement
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Erreur lors du chargement des variables d'environnement: %s", err)
	}

	// Port
	PORT := os.Getenv("PORT")

	// handler := func(res http.ResponseWriter, req *http.Request) {
	// 	fmt.Fprintf(res, "Marhaba Misterr Wick 🧘🏽🧘🏽🧘🏽") // Respond with "Hello, World!"
	//  }

	// Route principale de l'application
	router := http.NewServeMux()

	router.HandleFunc("/", homeHandler)
	router.HandleFunc("/auth", authHandler)

	// router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	// 	fmt.Fprint(w, "Bienvenue sur Smash Here")
	// 	fmt.Println(w, "\n [LOG] Bienvenue sur Smash Here")
	// })

	// router.HandleFunc("/auth", func(w http.ResponseWriter, req *http.Request) {
	// 	fmt.Fprint(w, "Routes pour s'inscrire teste")
	// 	fmt.Println(w, "\n [LOG] Routes pour s'inscrire teste")
	// })

	// fmt.Println("Application lancée : http://localhost" + PORT)

	// Lancement de la base de données
	database.InitDatabase()

	// Lancement de l'application
	if err := http.ListenAndServe(PORT, router); err != nil {
		fmt.Println("Erreur serveur : ", err)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Bienvenue sur Smash Here")
	fmt.Println(w, "\n [LOG] Bienvenue sur Smash Here")
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Routes pour s'inscrire teste")
	fmt.Println(w, "\n [LOG] Routes pour s'inscrire teste")
}
