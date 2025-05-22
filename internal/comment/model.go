package comment

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Commentaires liés aux utilisateurs & Roadmaps
type Comment struct {
	ID        primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Message   *string              `bson:"message,omitempty" json:"message"`
	Roadmap   primitive.ObjectID   `bson:"Roadmap,omitempty" json:"Roadmap"`
	Responses []primitive.ObjectID `bson:"Responses,omitempty" json:"Responses"`
	User      primitive.ObjectID   `bson:"User,omitempty" json:"User"`
	CreatedBy primitive.ObjectID   `bson:"CreatedBy,omitempty" json:"CreatedBy"`
	UpdatedBy primitive.ObjectID   `bson:"UpdatedBy,omitempty" json:"UpdatedBy"`
	CreatedAt time.Time            `bson:"createdAt,omitempty" json:"createdAt"`
	UpdatedAt time.Time            `bson:"updatedAt,omitempty" json:"updatedAt"`
}
