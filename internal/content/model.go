package content

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Contenu associé à une étape
type Content struct {
	ID        primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Title     *string              `bson:"title,omitempty" json:"title"`
	Type      *string              `bson:"type,omitempty" json:"type"` // "video", "article", "page", "roadmap"
	Link      *string              `bson:"link,omitempty" json:"link"`
	Steps     []primitive.ObjectID `bson:"Steps,omitempty" json:"Steps"`
	CreatedBy primitive.ObjectID   `bson:"CreatedBy,omitempty" json:"CreatedBy"`
	UpdatedBy primitive.ObjectID   `bson:"UpdatedBy,omitempty" json:"UpdatedBy"`
	CreatedAt time.Time            `bson:"createdAt,omitempty" json:"createdAt"`
	UpdatedAt time.Time            `bson:"updatedAt,omitempty" json:"updatedAt"`
}
