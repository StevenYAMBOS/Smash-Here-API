package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID             primitive.ObjectID `bson:"_id"`
	uid            string             `json:"uid"`
	username       *string            `json:"username" validate:"required", min=2, max=100`
	email          *string            `json:"email" validate:"email, required"`
	password       *string            `json:"password" validate:"required", min=6, max=100`
	profilePicture *string            `json:"profilePicture"`
	isSuperUser    bool               `json:"isSuperUser"`
	createdAt      time.Time          `json:"createdAt"`
	updatedAt      time.Time          `json:"updatedAt"`
	lastLogin      time.Time          `json:"lastLogin"`
	Roadmaps       []Roadmap          `json:"Roadmaps"`
	Bookmarks      []Roadmap          `json:"Bookmarks"`
}

type Roadmap struct {
	ID          primitive.ObjectID `bson:"_id"`
	uid         string             `json:"uid"`
	title       *string            `json:"title" validate:"required"`
	description *string            `json:"description" validate:"required"`
	cover       *string            `json:"cover"`
	published   bool               `json:"published"`
	createdAt   time.Time          `json:"createdAt"`
	updatedAt   time.Time          `json:"updatedAt"`
	Games       []Game             `json:"Game"`
	Users       []User             `json:"Users"`
}

type Game struct {
	ID          primitive.ObjectID `bson:"_id"`
	uid         string             `json:"uid"`
	title       *string            `json:"title" validate:"required"`
	description *string            `json:"description" validate:"required"`
	cover       *string            `json:"cover"`
	Type        string             `json:"type"`
	createdAt   time.Time          `json:"createdAt"`
	updatedAt   time.Time          `json:"updatedAt"`
	Roadmaps    []Roadmap          `json:"Roadmaps"`
}
