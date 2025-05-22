package user

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Utilisateur
type User struct {
	ID              primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Username        *string              `bson:"username,omitempty" json:"username"`
	Email           *string              `bson:"email,omitempty" json:"email"`
	Password        *string              `bson:"password,omitempty" json:"password"`
	ProfilePicture  *string              `bson:"profilePicture,omitempty" json:"profilePicture"`
	Type            *string              `bson:"type,omitempty" json:"type"`
	CreatedAt       time.Time            `bson:"createdAt,omitempty" json:"createdAt"`
	UpdatedAt       time.Time            `bson:"updatedAt,omitempty" json:"updatedAt"`
	LastLogin       time.Time            `bson:"lastLogin,omitempty" json:"lastLogin"`
	Bookmarks       []primitive.ObjectID `bson:"Bookmarks,omitempty" json:"Bookmarks"`
	StepsCreated    []primitive.ObjectID `bson:"StepsCreated,omitempty" json:"StepsCreated"`
	RoadmapsCreated []primitive.ObjectID `bson:"RoadmapsCreated,omitempty" json:"RoadmapsCreated"`
	RoadmapsStarted []primitive.ObjectID `bson:"RoadmapsStarted,omitempty" json:"RoadmapsStarted"`
	Comments        []primitive.ObjectID `bson:"Comments,omitempty" json:"Comments"`
}
