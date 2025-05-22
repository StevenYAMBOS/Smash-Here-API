package game

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Jeux liés aux roadmaps
type Game struct {
	ID            primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Title         *string              `bson:"title,omitempty" json:"title"`
	Subtitle      *string              `bson:"subTitle,omitempty" json:"subTitle"`
	Description   *string              `bson:"description,omitempty" json:"description"`
	Cover         *string              `bson:"cover,omitempty" json:"cover"`
	CreatedBy     primitive.ObjectID   `bson:"CreatedBy,omitempty" json:"CreatedBy"`
	UpdatedBy     primitive.ObjectID   `bson:"UpdatedBy,omitempty" json:"UpdatedBy"`
	Roadmaps      []primitive.ObjectID `bson:"Roadmaps,omitempty" json:"Roadmaps"`
	ViewsPerDay   *int                 `bson:"viewsPerDay,omitempty" json:"viewsPerDay"`
	ViewsPerWeek  *int                 `bson:"viewsPerWeek,omitempty" json:"viewsPerWeek"`
	ViewsPerMonth *int                 `bson:"viewsPerMonth,omitempty" json:"viewsPerMonth"`
	TotalViews    *int                 `bson:"totalViews,omitempty" json:"totalViews"`
	Published     *bool                `bson:"published,omitempty" json:"published"`
	CreatedAt     time.Time            `bson:"createdAt,omitempty" json:"createdAt"`
	UpdatedAt     time.Time            `bson:"updatedAt,omitempty" json:"updatedAt"`
}
