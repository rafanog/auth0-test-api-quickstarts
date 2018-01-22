# API Quickstart Tests

Tests for [API Quickstart samples](https://auth0.com/docs/quickstart/backend).

## Getting Started

Clone the repo and install the dependencies.

```bash
npm install
```

## Set up the `.env` file

Get a token for the management API with the scopes of: `create:client_grants`, `delete:client_grants`, `delete:clients`, `create:clients`, `update:resource_servers`, `delete:resource_servers` and `create:resource_servers`.
Checkout [Auth'0 documentation](https://auth0.com/docs/api/management/v2/tokens#get-a-token-manually) to know how to get a token for the [Management API](https://auth0.com/docs/api/info#management-api-v2).

Rename `.env.example` to `.env` and change the values for `AUTH0_DOMAIN` and `AUTH0_MANAGEMENT_API_TOKEN` with your Auth0's domain and a token for your API management.

## Running the tests

In order to run the tests execute:

```bash
npm test
```
