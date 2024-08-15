// api/jwt/jwt_token.go

package token

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/joho/godotenv"
)

func CreateToken(email string) (string, error) {
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

func VerifyToken(tokenString string) (*jwt.Token, error) {
	err := godotenv.Load(".env")
	if err != nil {
		return nil, fmt.Errorf("Erreur lors du chargement des variables d'environnement: %s", err)
	}
	SECRETE_KEY := []byte(os.Getenv("SECRETE_KEY"))

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("méthode de signature inattendue : %v", token.Header["alg"])
		}
		return SECRETE_KEY, nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}


func ProtectedHandler(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Header d'authentification manquant.", http.StatusUnauthorized)
			return
		}

		tokenString = strings.TrimSpace(tokenString[len("Bearer "):])

		token, err := VerifyToken(tokenString)
		if err != nil || !token.Valid {
			http.Error(w, "Token invalide.", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}
