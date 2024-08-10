// internal/routes/routes.go

package routes

import (
	"fmt"
	"log"
	"net/http"

	// "github.com/StevenYAMBOS/main/api/database"
	"github.com/joho/godotenv"
)

// ==================== ROUTEUR  ====================

func Router() http.Handler {
	// Variables d'environnement
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Erreur lors du chargement des variables d'environnement: %s", err)
	}

	router := http.NewServeMux()
	router.Handle("/auth/", AuthRouter())

	router.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// fmt.Fprintf(w, "Bienvenue sur Smash Here")
		fmt.Println("Bienvenue sur Smash Here")
	}))

	return router
}

// ---------- CONNEXION  ----------

func AuthRouter() http.Handler {
	authRouter := http.NewServeMux()

	authRouter.Handle("/login", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Route pour se connecter !")
	}))

	return http.StripPrefix("/auth", authRouter)
}
