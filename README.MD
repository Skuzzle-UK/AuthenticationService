# Authentication Service

Simple authentication service to allow registration of users and generation of JWT tokens etc.

The idea is that a user can register with a registration endpoint and be given a low level role.

Admins should then be able to edit the roles of users.

Users can then retrieve a token via another endpoint.

Example client included that consumes the generated token to allow access to controller endpoint

## Prerequisites:

- MongoDb and configuration added to appsettings.json
- Setup your own Encryption settings. You can use the provided endpoint https://localhost:7008/api/encryption/generate in the EncryptionController class to randomly generate your own key and initialisation vector