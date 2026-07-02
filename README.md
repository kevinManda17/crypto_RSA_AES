# Demonstration de handshake RSA/AES

Ce projet implemente un handshake cryptographique simple utilisant RSA-2048
pour echanger une cle symetrique AES-256. Apres le handshake, les messages
sont chiffres avec AES-256-GCM afin d'assurer la confidentialite et
l'authenticite des echanges entre le client et le serveur.

Le projet est compose de deux applications Python, un serveur et un client,
empaquetees dans des conteneurs Docker pour simplifier le lancement.

## Vue d'ensemble

* **Serveur (`./server`)** - Une application Flask qui genere ou charge une
  paire de cles RSA au demarrage, expose la cle publique via `/public-key`,
  recoit un `client_id` et une cle de session AES chiffree via `/handshake`,
  puis stocke les informations de session pendant une heure. Le serveur expose
  aussi `/message`, un endpoint qui attend un message chiffre avec AES-GCM.
  Un middleware Flask verifie `X-Session-ID`, journalise les tentatives non
  authentifiees, dechiffre le corps de la requete et rejette les sessions
  invalides avant le traitement du message.
* **Client (`./client`)** - Un client de demonstration en terminal. Il permet
  de recuperer la cle publique du serveur, generer une cle AES aleatoire,
  effectuer le handshake avec un identifiant client unique, envoyer des
  messages chiffres et afficher les reponses dechiffrees.
* **Docker Compose** - Le fichier `docker-compose.yml` cree deux conteneurs
  sur un reseau isole. Le serveur expose le port `5000` sur la machine hote,
  et un volume Docker conserve les cles RSA entre les redemarrages.
* **Diagrammes** - Le dossier `./diagrams` contient les fichiers PlantUML qui
  decrivent la sequence du handshake, les composants du serveur et
  l'infrastructure Docker.

## Lancer le projet sur Linux Mint

Depuis la racine du projet :

```bash
cd /home/kevin/Documents/KEVIN/programming/l4_cyber/crypto_RSA_AES
```

Construire l'image et lancer le serveur :

```bash
docker compose up --build -d rsa-server
```

Lancer le client interactif :

```bash
docker compose run --rm rsa-client-demo
```

Dans le menu du client, executer les etapes suivantes :

```text
1) Fetch server public key
2) Generate AES key
3) Perform handshake
4) Send message
```

Afficher les logs du serveur :

```bash
docker compose logs -f rsa-server
```

Arreter le projet :

```bash
docker compose down
```

Arreter le projet et supprimer les cles RSA persistees :

```bash
docker compose down -v
```

## Endpoints de l'API

`GET /public-key` retourne la cle publique RSA du serveur :

```json
{
  "algorithm": "RSA",
  "size": 2048,
  "key": "-----BEGIN PUBLIC KEY-----..."
}
```

`POST /handshake` recoit l'identifiant du client et la cle AES-256 chiffree
avec la cle publique RSA du serveur :

```json
{
  "client_id": "client-uuid",
  "encrypted_session_key": "base64-rsa-oaep-ciphertext"
}
```

La reponse contient la session a utiliser pour les requetes suivantes :

```json
{
  "status": "ok",
  "client_id": "client-uuid",
  "session_id": "session-uuid",
  "expires_at": "2026-04-03T12:00:00Z"
}
```

`POST /message` doit contenir l'en-tete `X-Session-ID` et un corps chiffre
avec AES-GCM :

```json
{
  "ciphertext": "base64-ciphertext",
  "nonce": "base64-96-bit-nonce",
  "tag": "base64-authentication-tag"
}
```

## Diagrammes PlantUML

Trois diagrammes UML sont fournis dans le dossier `diagrams` :

| Fichier | Description |
| --- | --- |
| `sequence.puml` | Diagramme de sequence du handshake, de l'echange de messages et du cycle chiffrement/dechiffrement. |
| `class.puml` | Diagramme de classes resumant les composants principaux du serveur. |
| `infra.puml` | Diagramme d'infrastructure montrant les conteneurs Docker, le reseau et le volume persistant. |

Pour generer les images PNG avec PlantUML :

```bash
cd diagrams
plantuml *.puml
```

## Licence

Ce projet est fourni a des fins pedagogiques. Il sert a comprendre un
handshake hybride RSA/AES, l'utilisation d'AES-GCM et l'organisation d'une
demonstration client-serveur avec Docker.
