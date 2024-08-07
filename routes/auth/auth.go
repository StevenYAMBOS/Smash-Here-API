package auth

import (
	"fmt"
	"log"
	"net/http"

	// "github.com/StevenYAMBOS/main/api/database"
	"github.com/joho/godotenv"
)

func AuthHandler() http.Handler {
	// Variables d'environnement
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Erreur lors du chargement des variables d'environnement: %s", err)
	}

	authRouter := http.NewServeMux()
	authRouter.HandleFunc("/login", LoginHandler)

	return http.StripPrefix("/auth", authRouter)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Routes pour s'inscrire teste")
	fmt.Println(w, "\n [LOG] Routes pour s'inscrire teste")
}
