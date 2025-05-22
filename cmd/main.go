package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/StevenYAMBOS/Smash-Here-API/database"
	"github.com/StevenYAMBOS/Smash-Here-API/internal/user/interfaces"
	"github.com/StevenYAMBOS/Smash-Here-API/pkg/config"
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

	// Routeur chi
	r := chi.NewRouter()
	// Middlewares globaux
	// r.Use(logger.RequestLogger)
	r.Use(cors.AllowAll().Handler)

	// Sous-routeurs par domaine
	interfaces.AuthRoutes(r)
	interfaces.UserRoutes(r)

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Erreur de config : %v", err)
	}
	fmt.Printf("➡️ Serveur démarré sur %s\n", cfg.Port)
	log.Fatal(http.ListenAndServe(cfg.Port, r))
}
