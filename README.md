
<p align="center">
  <img src="https://github.com/StevenYAMBOS/Smash-Here-API/blob/dev/assets/flame.webp" alt="Smash Here logo" width="400">
</p>

# Smash here API

## Description

Dépôt Back-End de l'application Smash Here.

## Technologies utilisées

- ![Go](https://img.shields.io/badge/go-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white)
- ![MongoDB](https://img.shields.io/badge/MongoDB-%234ea94b.svg?style=for-the-badge&logo=mongodb&logoColor=white)
- ![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)

## Fonctionnalités

- Authentification (inscription | connexion)
- Affichage de roadmaps
- Affichage des statistiques utilisateurs
- Modification de la progression d'un utilisateur
- Partage des roadmaps
- Notation (vote) des roadmaps

## Lancer le projet

### Installation

```shell
git clone https://github.com/StevenYAMBOS/Smash-Here-API
cd Smash-Here-API-main
```

### Variables d'environnements

Créer un fichier `.env` à la racine du projet (au même niveau que le fichier `go.mod`) et ajouter les informations suivantes :

```shell
PORT=
DATABASE_URL=
SECRETE_KEY=
```

### Lancement

```bash
go run cmd/main.go
```

## Liens utiles

- [Dépôt Front-End](https://github.com/StevenYAMBOS/Smash-Here-App)
- [Documentation](https://github.com/StevenYAMBOS/Smash-Here-API/wiki)
- [Smash Here Website]() (à venir)

## Autheur

### Steven YAMBOS

<a href="https://github.com/StevenYAMBOS"><img src="https://cdn-icons-png.flaticon.com/512/25/25231.png" width="30px" alt="" /><a/>
<a href="https://x.com/StevenYambos"><img src="https://img.freepik.com/vecteurs-libre/nouvelle-conception-icone-x-du-logo-twitter-2023_1017-45418.jpg?size=338&ext=jpg&ga=GA1.1.2008272138.1722902400&semt=ais_hybrid" width="30px" alt="X Steven YAMBOS" /><a/>

## License

[MIT](https://www.youtube.com/watch?v=3FmN46XQius)
