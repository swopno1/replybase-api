# API Routes

This document lists all the available API routes in the application.

## User Authentication

- `POST /auth/register` - Registers a new user.
- `POST /auth/login` - Logs in a user.

## Social Authentication

- `GET /auth/facebook/login` - Initiates the Facebook login process.
- `GET /auth/facebook/callback_login` - Handles the Facebook login callback.
- `GET /auth/facebook/connect` - Connects a Facebook account to an existing user.
- `GET /auth/facebook/callback_connect` - Handles the Facebook connect callback.
- `POST /auth/facebook/deauthorize` - Handles the Facebook deauthorization callback.
- `POST /auth/facebook/delete-data` - Handles the Facebook data deletion request.
- `GET /auth/google/login` - Initiates the Google login process.
- `GET /auth/google/callback` - Handles the Google login callback.

## Webhooks

- `GET /webhooks/meta` - Verifies the Meta webhook.
- `POST /webhooks/meta` - Handles incoming messages from Meta.

## Tenant

- `GET /tenant/status` - Returns the connected platforms for a tenant.
- `POST /tenant/whatsapp` - Connects a WhatsApp account to a tenant.

## Health

- `GET /health` - Checks the health of the application.
