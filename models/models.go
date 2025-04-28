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

// Utilisateur
type User struct {
	ID              primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Username        *string              `bson:"username,omitempty" json:"username"`
	Email           *string              `bson:"email,omitempty" json:"email"`
	Password        *string              `bson:"password,omitempty" json:"password"`
	ProfilePicture  *string              `bson:"profileImage,omitempty" json:"profileImage"`
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

// Roadmap
type Roadmap struct {
	ID            primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Title         *string              `bson:"title,omitempty" json:"title"`
	SubTitle      *string              `bson:"subTitle,omitempty" json:"subTitle"`
	Description   *string              `bson:"description,omitempty" json:"description"`
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

// Étape d'une roadmap
type Step struct {
	ID            primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Title         *string              `bson:"title,omitempty" json:"title"`
	Subtitle      *string              `bson:"subtitle,omitempty" json:"subtitle"`
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

// Progression utilisateur sur une roadmap
type Progression struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	User      primitive.ObjectID `bson:"User,omitempty" json:"User"`
	Roadmap   primitive.ObjectID `bson:"Roadmap,omitempty" json:"Roadmap"`
	Step      primitive.ObjectID `bson:"Step,omitempty" json:"Step"`
	Status    *string            `bson:"status,omitempty" json:"status"` // "pending", "inProgress", "done", "skipped"
	UpdatedAt time.Time          `bson:"updatedAt,omitempty" json:"updatedAt"`
}

// Tags pour roadmaps, étapes et contenus
type Tag struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name      *string            `bson:"name,omitempty" json:"name"`
	CreatedBy primitive.ObjectID `bson:"CreatedBy,omitempty" json:"CreatedBy"`
	UpdatedBy primitive.ObjectID `bson:"UpdatedBy,omitempty" json:"UpdatedBy"`
	CreatedAt time.Time          `bson:"createdAt,omitempty" json:"createdAt"`
	UpdatedAt time.Time          `bson:"updatedAt,omitempty" json:"updatedAt"`
}

// Jeux liés aux roadmaps
type Game struct {
	ID            primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Title         *string              `bson:"title,omitempty" json:"title"`
	Subtitle      *string              `bson:"subtitle,omitempty" json:"subtitle"`
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
