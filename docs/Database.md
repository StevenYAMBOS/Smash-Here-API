# Base de données

**MongoDB** <img src="https://www.svgrepo.com/show/331488/mongodb.svg" width="30px" alt="MongoDB logo" />

[Schéma UML](https://www.google.com)

## Collections

### user

Collection relative aux utilisateurs.

```json
id : String
username : String
email : String
password : String
profilePicture : String
isSuperUser : Boolean
createdAt : Timestamp
updatedAt : Timestamp
lastLogin : Timestamp
Roadmaps : Référence à la collection 'roadmap'
Bookmarks : Référence à la collection 'roadmap'
```

### roadmap

Collection relative aux Roadmaps.

```json
title : String
description : String
cover : String
published : Boolean
createdAt : Timestamp
updatedAt : Timestamp
Games : Tableau de référence à la collection 'game'
Users : Tableau de référence à la collection 'user'
```

### game

Collection relative aux jeux disponibles sur la plateforme.

```json
title : String
description : String
type : String
cover : String
createdAt : Timestamp
updatedAt : Timestamp
Roadmaps : Tableau de référence à la collection 'roadmap'
```
