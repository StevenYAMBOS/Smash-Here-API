// models/models.go

package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// les champs doivent avoir des majuscules sinon on a l'erreur : "struct field 'nom_du_champ' has json tag but is not exported"

type User struct {
	ID             primitive.ObjectID `bson:"_id"`
	Uid            string             `json:"uid"`
	Username       *string            `json:"username"`
	Email          *string            `json:"email"`
	Password       *string            `json:"password"`
	ProfilePicture *string            `json:"profilePicture"`
	IsSuperUser    bool               `json:"isSuperUser"`
	CreatedAt      time.Time          `json:"createdAt"`
	UpdatedAt      time.Time          `json:"updatedAt"`
	LastLogin      time.Time          `json:"lastLogin"`
	Roadmaps       []Roadmap          `json:"Roadmaps"`
	Bookmarks      []Roadmap          `json:"Bookmarks"`
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
