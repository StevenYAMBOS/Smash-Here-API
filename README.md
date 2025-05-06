# Smash here API

<p align="center">
  <img src="https://3238leblogdemarvelll-1278.kxcdn.com/wp-content/uploads/2012/05/Street-Fighter-X-Tekken-Banniere.jpg" alt="Smash Here banner" width="738">
</p>

## Description

**SMASH HERE** est une **plateforme e-sport** spécialisée dans les **jeux de combat**, destinée à **centraliser** et **structurer** l’apprentissage et la **progression** des joueurs. Elle repose sur des roadmaps **interactives** et **personnalisées**, conçues pour guider les joueurs à travers des étapes clés de progression, adaptées à leur niveau (débutant, intermédiaire, avancé) et à leurs besoins spécifiques (jeu, personnage, stratégie).
Les roadmaps sont des guides qui décrive les étapes à suivre pour arriver à un objectif. La plateforme disposera de plusieurs type de roadmap en fonction des jeux, des personnages ou encore des niveaux des joueurs.

La plateforme cible un large éventail d’utilisateurs, incluant les joueurs passionnés (amateurs et professionnels) et les coachs e-sportifs. Ces roadmaps sont conçues pour :

* **Centraliser l’information** aujourd’hui dispersée sur différentes plateformes (YouTube, X, Reddit, Discord, Twitch).
* **Simplifier l’apprentissage** grâce à des parcours interactifs et évolutifs.
* Offrir des **outils de suivi** personnalisés pour optimiser les performances.
* Fédérer une communauté active, tout en proposant des solutions adaptées aux besoins de chaque utilisateur.

Missions principales :

- **Centralisation des ressources :** Regrouper et valider les informations pour éviter la dispersion.
- **Apprentissage structuré :** Proposer des parcours pédagogiques clairs et interactifs.
- **Personnalisation de l’expérience utilisateur :** Offrir des outils de suivi et d’ajustement des roadmaps.
- Engagement communautaire : Créer un espace collaboratif pour les joueurs et les coachs.

## Technologies utilisées

- **Golang** <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/0/05/Go_Logo_Blue.svg/1200px-Go_Logo_Blue.svg.png" width="30px" alt="Golang logo" />
- **MongoDB** <img src="https://www.svgrepo.com/show/331488/mongodb.svg" width="30px" alt="MongoDB logo" />
- **Docker** <img src="https://cdn4.iconfinder.com/data/icons/logos-and-brands/512/97_Docker_logo_logos-512.png" width="30px" alt="Docker logo" />

## Fonctionnalités

- Authentification (inscription | connexion)
- Affichage de roadmaps
- Affichage des statistiques utilisateurs
- Modification de la progression d'un utilisateur
- Partage des roadmaps
- Notation (vote) des roadmaps

## Organisation du dépôt ⚠️

L'organisation des branches du dépôt est structurée pour faciliter le développement, les tests, et le déploiement en production. Voici les principales branches utilisées :

- **`main`** (vous vous trouvez ici) :
  Point d'entrée du projet, contient tous les documents nécessaires à la compréhension du projet. 
- **`dev`** :  
  La branche principale de développement continu. Elle sert d'environnement bac à sable pour les développeurs où toutes les nouvelles fonctionnalités et corrections de bugs sont intégrées après validation initiale.

- **`pre-prod`** :  
  Cette branche est destinée à présenter les fonctionnalités au client. Une fois que les développements de la branche `dev` sont stabilisés et validés, ils sont fusionnés dans cette branche pour des démonstrations.

- **`prod`** :  
  La branche finale de production qui contient la version stable et prête à être déployée de l'application. Elle est mise à jour uniquement lorsque les changements dans `pre-prod` sont entièrement validés.

**Bonnes pratiques :**

- Tester les fonctionnalités dans la branche `dev` avant de les intégrer dans `pre-prod`.
- Ne jamais effectuer de développement direct sur les branches `pre-prod` et `prod`.
- Maintenir la branche `prod` uniquement avec du code stable et prêt pour les utilisateurs finaux.

## Installation

```shell
git clone https://github.com/StevenYAMBOS/Smash-Here-API
cd Smash-Here-API-main
```

## Lancer l'application

```bash
go run cmd/main.go
```

## Liens utiles

- [Dépôt Front-End]() (à venir)
- [Smash Here Website]() (à venir)

## Autheur

### Steven YAMBOS

<a href="https://github.com/StevenYAMBOS"><img src="https://cdn-icons-png.flaticon.com/512/25/25231.png" width="30px" alt="" /><a/>
<a href="https://x.com/StevenYambos"><img src="https://img.freepik.com/vecteurs-libre/nouvelle-conception-icone-x-du-logo-twitter-2023_1017-45418.jpg?size=338&ext=jpg&ga=GA1.1.2008272138.1722902400&semt=ais_hybrid" width="30px" alt="X Steven YAMBOS" /><a/>

## License

[MIT](https://www.youtube.com/watch?v=3FmN46XQius)
