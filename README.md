# RSA Handshake Demonstration

This project implements a simple cryptographic handshake using an
asymmetric algorithm (RSA‑2048) to exchange a symmetric key
for authenticated communication with AES‑256‑GCM.  It is composed of
two Python components, a server and a client, packaged as
Docker containers to simplify deployment.

## Overview

* **Server (`./server`)** – A Flask application that
  generates or loads an RSA key pair on startup, exposes the
  public key via `/public-key`, accepts an encrypted AES key via
  `/handshake`, stores session information with a one hour TTL, and
  exposes a `/message` endpoint that expects an AES‑GCM encrypted
  payload.  Messages are decrypted, processed and re‑encrypted before
  being returned.
* **Client (`./client`)** – A terminal‑based demo written in
  Python.  It guides the user through retrieving the server’s
  public key, generating a random AES key, performing the
  handshake and exchanging encrypted messages.  A small menu
  orchestrates each step and demonstrates failure cases (e.g.
  invalid sessions).
* **Docker Compose** – The `docker-compose.yml` file creates
  two containers on an isolated network.  The server exposes port
  5000 on the host, and a volume is used to persist RSA keys across
  restarts.  The client container depends on the server and uses the
  service name to reach it internally.
* **Diagrams** – Under `./diagrams` you will find PlantUML files
  describing the sequence of the handshake, a class diagram of
  the server internals and a simple deployment diagram.  If you
  have PlantUML installed you can generate images by running
  `plantuml *.puml` in that directory.

## Running the demo

1. **Build and start the containers**

   ```bash
   docker-compose up --build
   ```

   The server will listen on port 5000.  The first run will
   generate an RSA key pair and store it in the `rsa-keys` volume.

2. **Interact with the client**

   In a separate terminal you can run the demo client within the
   Docker network:

   ```bash
   docker-compose run --rm rsa-client-demo
   ```

   A menu will appear allowing you to fetch the public key,
   generate an AES key, perform the handshake and send encrypted
   messages.  You can also run an automated demo that performs all
   steps sequentially.

3. **Access the API directly**

   You may also interact with the server using curl or Postman on
   `http://localhost:5000` when running on the same machine, or
   replace `localhost` with your host’s IP address (e.g.
   `172.20.10.5`) when accessing it from another device on your
   network.

## PlantUML diagrams

Three UML diagrams are included as text files in the `diagrams`
directory:

| file                | description |
|---------------------|-------------|
| `sequence.puml`     | Sequence diagram of the handshake, message exchange and decryption/response cycle. |
| `class.puml`        | Class diagram summarising the major components in the server implementation (key manager, session store, crypto service, middleware and Flask routes). |
| `infra.puml`        | Deployment diagram illustrating the two containers, the Docker bridge network, the persisted volume and the interaction from host and mobile devices. |

To generate PNG files from these definitions you can install
PlantUML locally and run:

```bash
cd diagrams
plantuml *.puml
```

## License

This project is provided for educational purposes and does not
constitute production‑ready cryptographic infrastructure.  Use it to
learn about RSA handshakes, AES‑GCM and Docker networking but
apply appropriate security audits before deploying similar
mechanisms in real applications.