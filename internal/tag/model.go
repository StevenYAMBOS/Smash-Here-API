package tag

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Tags pour roadmaps, étapes et contenus
type Tag struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name      *string            `bson:"name,omitempty" json:"name"`
	CreatedBy primitive.ObjectID `bson:"CreatedBy,omitempty" json:"CreatedBy"`
	UpdatedBy primitive.ObjectID `bson:"UpdatedBy,omitempty" json:"UpdatedBy"`
	CreatedAt time.Time          `bson:"createdAt,omitempty" json:"createdAt"`
	UpdatedAt time.Time          `bson:"updatedAt,omitempty" json:"updatedAt"`
}
