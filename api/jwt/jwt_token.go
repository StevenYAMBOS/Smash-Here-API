package token

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/joho/godotenv"
)

func createToken(email string) (string, error) {
	// Variable d'environnement
	err := godotenv.Load("SECRETE_KEY")
	if err != nil {
		log.Fatalf("Erreur lors du chargement des variables d'environnement: %s", err)
	}

	SECRETE_KEY := os.Getenv("SECRETE_KEY")

	token := jwt.NewWithClaims(jwt.SigningMethodES256,
		jwt.MapClaims{
			"email": email,
			"exp":   time.Now().Add(time.Hour * 24).Unix(),
		})

	tokenString, err := token.SignedString(SECRETE_KEY)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func verifyToken(tokenString string) error {
	err := godotenv.Load("SECRETE_KEY")
	if err != nil {
		log.Fatalf("Erreur lors du chargement des variables d'environnement: %s", err)
	}
	SECRETE_KEY := os.Getenv("SECRETE_KEY")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return SECRETE_KEY, nil
	})

	if err != nil {
		return err
	}

	if !token.Valid {
		return fmt.Errorf("token invalide")
	}

	return nil
}
