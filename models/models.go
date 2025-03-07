/*
Pourquoi certains champs sont des pointeurs et d'autres non ?

Dans la structure User, certains champs sont des pointeurs (*string) alors que d'autres sont des valeurs normales (bool, time.Time). Voici les raisons principales :

    Différenciation entre valeur nulle et valeur vide
        Un *string permet de stocker nil, ce qui signifie que la valeur n'est pas définie.
        Un string non pointé ne peut jamais être nil, il aura toujours une valeur par défaut ("", chaîne vide).
        Cela est utile pour savoir si un champ a été explicitement défini par l'utilisateur ou non.

    Optimisation de la mémoire et des performances
        Si les champs Username, Email, Password et ProfilePicture sont facultatifs ou rarement utilisés, utiliser des pointeurs évite d’allouer de la mémoire pour des valeurs inutilisées.
        Pour les types primitifs (comme bool et time.Time), utiliser un pointeur peut être pertinent si tu veux pouvoir représenter une absence de valeur (nil), mais dans la plupart des cas, une valeur par défaut (false pour bool, 0001-01-01 00:00:00 +0000 UTC pour time.Time) est suffisante.

    Interopérabilité avec les bibliothèques de validation et JSON
        Les bibliothèques de validation comme binding:"required" de Gin attendent des pointeurs pour savoir si une valeur a été fournie ou non.
        Avec JSON, si un champ est un pointeur et est nil, il sera omis dans le JSON généré.
*/

package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// les champs doivent avoir des majuscules sinon on a l'erreur : "struct field 'nom_du_champ' has json tag but is not exported"

type User struct {
	ID              primitive.ObjectID `bson:"_id"`
	Username        *string            `json:"username" bson:"username" binding:"required"`
	Email           *string            `json:"email" bson:"email" binding:"required"`
	Password        *string            `json:"password" bson:"password" binding:"required"`
	ProfilePicture  *string            `json:"profilePicture" bson:"profilePicture"`
	IsSuperUser     bool               `json:"isSuperUser" bson:"isSuperUser"`
	CreatedAt       time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt       time.Time          `json:"updatedAt" bson:"updatedAt"`
	LastLogin       time.Time          `json:"lastLogin" bson:"lastLogin"`
	RoadmapsStarted []Roadmap          `json:"RoadmapsStarted" bson:"RoadmapsStarted"`
	Bookmarks       []Roadmap          `json:"Bookmarks" bson:"Bookmarks"`
}

type Roadmap struct {
	ID          primitive.ObjectID `bson:"_id"`
	Uid         string             `json:"uid"`
	Title       *string            `json:"title"`
	Description *string            `json:"description"`
	Cover       *string            `json:"cover"`
	Published   bool               `json:"published"`
	CreatedAt   time.Time          `json:"createdAt"`
	UpdatedAt   time.Time          `json:"updatedAt"`
	Games       []Game             `json:"Game"`
	Users       []User             `json:"Users"`
}

type Game struct {
	ID          primitive.ObjectID `bson:"_id"`
	Uid         string             `json:"uid"`
	Title       *string            `json:"title"`
	Description *string            `json:"description"`
	Cover       *string            `json:"cover"`
	Type        string             `json:"type"`
	CreatedAt   time.Time          `json:"createdAt"`
	UpdatedAt   time.Time          `json:"updatedAt"`
	Roadmaps    []Roadmap          `json:"Roadmaps"`
}
