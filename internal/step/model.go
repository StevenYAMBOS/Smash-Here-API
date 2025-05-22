package step

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Étape d'une roadmap
type Step struct {
	ID            primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Title         *string              `bson:"title,omitempty" json:"title"`
	Subtitle      *string              `bson:"subTitle,omitempty" json:"subTitle"`
	Description   *string              `bson:"description,omitempty" json:"description"`
	Roadmaps      []primitive.ObjectID `bson:"Roadmaps,omitempty" json:"Roadmaps"`
	Contents      []primitive.ObjectID `bson:"Contents,omitempty" json:"Contents"`
	PreviousSteps []primitive.ObjectID `bson:"PreviousSteps,omitempty" json:"PreviousSteps"`
	NextSteps     []primitive.ObjectID `bson:"NextSteps,omitempty" json:"NextSteps"`
	CreatedBy     primitive.ObjectID   `bson:"CreatedBy,omitempty" json:"CreatedBy"`
	UpdatedBy     primitive.ObjectID   `bson:"UpdatedBy,omitempty" json:"UpdatedBy"`
	CreatedAt     time.Time            `bson:"createdAt,omitempty" json:"createdAt"`
	UpdatedAt     time.Time            `bson:"updatedAt,omitempty" json:"updatedAt"`
}
