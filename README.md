# superagent-test

A minimal Express HTTP service exposing a health endpoint.

## Project structure

| Path | Purpose |
| --- | --- |
| `src/app.js` | Express app with the `GET /health` route |
| `src/server.js` | Starts the HTTP server on `PORT` (default `3000`) |
| `test/health.test.js` | Tests for the health endpoint using Node's built-in test runner |

## Getting started

```bash
npm install
npm start
curl http://localhost:3000/health
```

The health endpoint responds with HTTP 200 and:

```json
{ "status": "ok" }
```

## Tests

```bash
npm test
```
