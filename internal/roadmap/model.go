package roadmap

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Roadmap
type Roadmap struct {
	ID            primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Title         *string              `bson:"title,omitempty" json:"title"`
	SubTitle      *string              `bson:"subTitle,omitempty" json:"subTitle"`
	Description   *string              `bson:"description,omitempty" json:"description"`
	Cover         *string              `bson:"cover,omitempty" json:"cover"`
	Published     *bool                `bson:"published,omitempty" json:"published"`
	Premium       *bool                `bson:"premium,omitempty" json:"premium"`
	ViewsPerDay   *int                 `bson:"viewsPerDay,omitempty" json:"viewsPerDay"`
	ViewsPerWeek  *int                 `bson:"viewsPerWeek,omitempty" json:"viewsPerWeek"`
	ViewsPerMonth *int                 `bson:"viewsPerMonth,omitempty" json:"viewsPerMonth"`
	TotalViews    *int                 `bson:"totalViews,omitempty" json:"totalViews"`
	CreatedBy     primitive.ObjectID   `bson:"CreatedBy,omitempty" json:"CreatedBy"`
	UpdatedBy     primitive.ObjectID   `bson:"UpdatedBy,omitempty" json:"UpdatedBy"`
	CreatedAt     time.Time            `bson:"createdAt,omitempty" json:"createdAt"`
	UpdatedAt     time.Time            `bson:"updatedAt,omitempty" json:"updatedAt"`
	Comments      []primitive.ObjectID `bson:"Comments,omitempty" json:"Comments"`
	Games         []primitive.ObjectID `bson:"Games,omitempty" json:"Games"`
	Steps         []primitive.ObjectID `bson:"Steps,omitempty" json:"Steps"`
	Tags          []primitive.ObjectID `bson:"Tags,omitempty" json:"Tags"`
}

// Progression utilisateur sur une roadmap
type Progression struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	User      primitive.ObjectID `bson:"User,omitempty" json:"User"`
	Roadmap   primitive.ObjectID `bson:"Roadmap,omitempty" json:"Roadmap"`
	Step      primitive.ObjectID `bson:"Step,omitempty" json:"Step"`
	Status    *string            `bson:"status,omitempty" json:"status"` // "pending", "inProgress", "done", "skipped"
	UpdatedAt time.Time          `bson:"updatedAt,omitempty" json:"updatedAt"`
}
