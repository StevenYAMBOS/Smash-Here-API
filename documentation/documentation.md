# Documentation

- Mise à jour le : **15/04/2025**
- Par : **Steven YAMBOS**

## Description

Dépôt Back-End de l'application Smash Here.

## Technologies utilisées

- ![Go](https://img.shields.io/badge/go-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white)
- ![MongoDB](https://img.shields.io/badge/MongoDB-%234ea94b.svg?style=for-the-badge&logo=mongodb&logoColor=white)
- ![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)

## Base de données (MongoDB)

Base de données **MongoDB** :

- Nom du cluster : `smash-here`
- Nom d'utilisateur : stevenyambos
- Nom de la base de données dans le cluster `smash-here` : `smashheredb`

### Bonnes pratiques

- Les tables sont au singulier et en miniscule (exemple : `user`)

### Collections

Collections principales et leur structure.

#### Collection `user`

Les utilisateurs sont au cœur de la plateforme. La collection `user` contient des informations sur les comptes et les préférences des utilisateurs.

Structure :

```json
{
  "Bookmarks": ["ObjectId"], // Références à la collection `roadmap`
  "RoadmapsStarted": ["ObjectId"], // Références à la collection `roadmap`
  "RoadmapsCreated": ["ObjectId"], // Références à la collection `roadmap`
  "StepsCreated": ["ObjectId"], // Références à la collection `step`
  "username": "string",
  "email": "string",
  "password": "string",
  "type": "string", // "superadmin", "coach", "user"
  "profilePicture": "string", // URL vers l'image de profil
  "createdAt": "timestamp",
  "updatedAt": "timestamp",
  "lastLogin": "timestamp"
}
```

Explications des champs :

- `RoadmapsStarted` : Liste des roadmpaps où l'utilisateur a une progression.
- `RoadmapsCreated` : Liste des roadmpaps créées par l'utilisateur.
- `StepsCreated` : Liste des étapes créées par l'utilisateur.
- `Bookmarks` : Roadmaps misent en signet.
- `type` : Type d'utilisateur :
 -> `superadmin`
 -> `coach`
 -> `user`
- `username` : Pseudo.
- `email` : Adresse Email.
- `profilePicture` : Image de profil.
- `password` : Mot de passe.
- `createdAt` : Date de création du document.
- `updatedAt` : Date de mise à jour du document.
- `lastLogin` : Dernière connexion de l'utilisateur.

---

#### Collection `roadmap`

Les roadmaps structurent les parcours d’apprentissage pour les utilisateurs. Chaque roadmap est associée à plusieurs étapes et éventuellement à plusieurs jeux.

Structure :

```json
{
  "Games": ["ObjectId"], // Références à la collection `game`
  "Steps": ["ObjectId"], // Références à la collection `step`
  "Tags": ["ObjectId"], // Références à la collection `tag`
  "CreatedBy": "ObjectId", // Référence à la collection `user`
  "UpdatedBy": "ObjectId", // Référence à la collection `user`
  "title": "string",
  "subTitle": "string",
  "description": "string",
  "published": "boolean",
  "premium": "boolean",
  "viewsPerDay": "number",
  "viewsPerWeek": "number",
  "viewsPerMonth": "number",
  "totalViews": "number",
  "createdAt": "timestamp",
  "updatedAt": "timestamp"
}
```

Explication des champs :

- `Games` : Liste des jeux auxquels appartient la roadmap.
- `Steps` : Liste des étapes de la roadmap.
- `Tags` : Liste des tags de la roadmap.
- `CreatedBy` : Utilisateur qui a créé le document.
- `UpdatedBy` : Dernier utilisateur qui a mit à jour les informations du jeu.
- `title` : Nom de la roadmap.
- `subtitle` : Sous titre de de roadmap.
- `description` : Description de la roadmap.
- `viewsPerDay` : Nombre de vues par jour de la page du jeu.
- `viewsPerWeek` : Nombre de vues par semaines de la page du jeu.
- `viewsPerMonths` : Nombre de vues par mois de la page du jeu.
- `totalViews` : Nombre de vues total.
- `published` : Statut de publication de la roadmap.
- `premium` : Roadmap payante/exclusive.
- `createdAt` : Date de création du document.
- `updatedAt` : Date de mise à jour du document.

---

#### Collection `step`

Les étapes sont les éléments de base des roadmaps, guidant les utilisateurs dans leur progression.

Structure :

```json
{
  "Roadmaps": ["ObjectId"], // Références à la collection `roadmap`
  "Contents": ["ObjectId"], // Références à la collection `content`
  "PreviousSteps": ["ObjectId"], // Références aux étapes précédentes
  "NextSteps": ["ObjectId"], // Références aux étapes suivantes
  "title": "string",
  "subtitle": "string",
  "description": "string",
  "createdAt": "timestamp",
  "updatedAt": "timestamp"
}
```

Explications des champs :

- `Roadmaps` : Liste des roadmap auxquelles appartient cette étape.
- `Contents` : Liste des contenus de cette étape.
- `PreviousSteps` : Liste des étapes précédentes de cette étape. Généralement il n'y aura qu'une étape précédente/parent. Nous préférons utiliser un tableau car une étape peut appartenir à plusieurs roadmaps.
- `NextSteps` : Liste des étapes suivantes de cette étape. Généralement il n'y aura qu'une étape suivante/enfant. Nous préférons utiliser un tableau car une étape peut appartenir à plusieurs roadmaps.
- `title` : Titre de l'étape.
- `subtitle` : Sous-titre de l'étape.
- `description` : Description de l'étape.

---

#### Collection `content`

Les contenus fournissent des ressources pour les étapes, comme des vidéos, des articles, ou des liens externes.

Structure :

```json
{
  "CreatedBy": "ObjectId", // Référence à la collection `user`
  "UpdatedBy": "ObjectId", // Référence à la collection `user`
  "title": "string",
  "type": "string", // "video", "article", "page", "roadmap"
  "link": "string", // Lien vers le contenu
  "createdAt": "timestamp",
  "updatedAt": "timestamp"
}
```

Explications des champs :

- `CreatedBy` : Utilisateur qui a créé ce contenu (le développeur/admin).
- `UpdatedBy` : Utilisateur qui a mit à jour ce contenu (le développeur/admin).
- `type` : Type du contenu. Le contenu peut être un(e) :
 -> `video`
 -> `article`
 -> `page` (page X/Twitter d'un utilisateur, chaîne YouTube, page Reddit, groupe Discord, site internet)
 -> `roadmap` (autres roadmaps).
- `link` : Lien du contenu.
- `title` : Titre/nom du contenu.
- `createdAt` : Date de création du document.
- `updatedAt` : Date de mise à jour du document.

---

#### Collection `progression`

La progression permet de suivre l’état d’avancement des utilisateurs dans les étapes de chaque roadmap.

Structure :

```json
{
  "User": "ObjectId", // Référence à la collection `user`
  "Roadmap": "ObjectId", // Référence à la collection `roadmap`
  "Step": "ObjectId", // Référence à la collection `step`
  "status": "string", // "pending", "inProgress", "done", "skipped"
  "updatedAt": "timestamp"
}
```

Explications des champs :

- `User` : Référence vers l'utilisateur à qui cette progression appartient.
- `Roadmap` : Référence vers la roadmap concernée.
- `Step` : Référence vers l'étape concernée.
- `status` : Statut de l'étape. Valeurs possibles :
    -> `pending` : état neutre (par défaut).
    -> `skip` : étape passée.
    -> `inProgress` : étape en cours.
    -> `done` : étape validée.
- `updatedAt` : Date de la dernière mise à jour du statut par l'utilisateur.

---

#### Collection `tag`

Les tags permettent de catégoriser les roadmaps, étapes, et contenus.

Structure :

```json
{
  "CreatedBy": "ObjectId", // Référence à la collection `user`
  "UpdatedBy": "ObjectId", // Référence à la collection `user`
  "name": "string",
  "createdAt": "timestamp",
  "updatedAt": "timestamp"
}
```

Explications des champ :

- `CreatedBy` : Utilisateur qui a créé le tag (les développeurs/admins).
- `UpdatedBy` : Utilisateur qui a modifié le tag (les développeurs/admins).
- `name` : Nom du tag.
- `createdAt` : Date de création du document.
- `updatedAt` : Date de mise à jour du document.

---

#### Collection `game`

Les jeux organisent les roadmaps en fonction de leur affiliation à un titre spécifique.

Structure :

```json
{
  "title": "string",
  "subtitle": "string",
  "description": "string",
  "Roadmaps": ["ObjectId"], // Références à la collection `roadmap`
  "CreatedBy": "ObjectId", // Référence à la collection `user`
  "UpdatedBy": "ObjectId", // Référence à la collection `user`
  "viewsPerDay": "number",
  "viewsPerWeek": "number",
  "viewsPerMonth": "number",
  "totalViews": "number",
  "createdAt": "timestamp",
  "updatedAt": "timestamp"
}
```

Explications des champs :

- `Roadmaps` : Liste des roadmaps appartenant ou liées à ce jeu.
- `CreatedBy` : Utilisateur qui a créé le jeu.
- `UpdatedBy` : Dernier utilisateur qui a mit à jour les informations du jeu.
- `title` : Nom du jeu.
- `subtitle` : Sous titre du jeu.
- `description` : Description du jeu.
- `viewsPerDay` : Nombre de vues par jour de la page du jeu.
- `viewsPerWeek` : Nombre de vues par semaines de la page du jeu.
- `viewsPerMonths` : Nombre de vues par mois de la page du jeu.
- `totalViews` : Nombre de vues total.
- `viewsPerMonths` : Nombre de vues par mois de la page du jeu.
- `createdAt` : Date de création du document.
- `updatedAt` : Date de mise à jour du document.

---
