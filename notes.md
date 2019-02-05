Dependencies 
- express
- helmet
- nodemon -D
- knex/sqlite3

- add bcrypt
z
Oauth2: authorization framework
OpenID Connect: authentication protocol

tokens: 
- authentication token: Who are you?
- acess/authorization token: What can you do?
- refresh token

working w/ JWTs

SERVER
- Producing the token
- Sending the token to the client 
- reading the token from the client
- Verifying that the token is valid
- Providing payload from the token to the rest of the app

CLIENT
- Store the token and hold on to it
- Send the token on every request
- On logout, destroy the token

users *---* roles
users *---* permissions
users *---* permissions

in Oauth2, permissions are called scopes ('read:salary','edit:salary')
