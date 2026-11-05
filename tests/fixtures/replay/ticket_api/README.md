# ticket-api

A small Express service for support tickets, scoped by organisation.
Tokens are HS256 JWTs carrying `sub`, `orgId` and `role`.
