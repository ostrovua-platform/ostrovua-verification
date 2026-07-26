# Backend Endpoint Inventory

Source commit: `05b1600b2e7bf6aafbaf8b43983f1105ec4443ab`

This inventory is derived from the route registrations in `Server/server.js`
and `Server/biometric_service/app.py`. It contains paths and methods only; it
contains no hostnames, credentials or production data.

## Authentication and account

| Method | Path |
|---|---|
| `POST` | `/auth/register` |
| `POST` | `/auth/login` |
| `POST` | `/auth/logout` |
| `POST` | `/auth/logout-all` |
| `GET` | `/auth/introspect` |
| `POST` | `/auth/change-password` |
| `POST` | `/auth/forgot-password` |
| `POST` | `/auth/reset-password` |
| `DELETE` | `/auth/account` |
| `GET` | `/auth/health` |

## Invitation and profile

| Method | Path |
|---|---|
| `POST` | `/auth/invite` |
| `GET` | `/auth/invite/:token` |
| `POST` | `/auth/accept-invite` |
| `POST` | `/auth/update-avatar` |
| `POST` | `/auth/update-theme` |
| `POST` | `/auth/upload` |
| `POST` | `/auth/device-token` |
| `POST` | `/auth/device-token/remove` |

## OAuth and Telegram

| Method | Path |
|---|---|
| `GET` | `/auth/google` |
| `GET` | `/auth/google/callback` |
| `GET` | `/auth/google/error` |
| `GET` | `/auth/github` |
| `GET` | `/auth/github/callback` |
| `GET` | `/auth/github/error` |
| `GET` | `/auth/telegram/widget` |
| `POST` | `/auth/telegram` |

Google and GitHub registrations have configured and unavailable branches in
the source. They are single public paths at runtime, not duplicate endpoints.

## Verification

| Method | Path |
|---|---|
| `POST` | `/auth/verify/challenge` |
| `POST` | `/auth/verify/attest-key` |
| `POST` | `/auth/verify/ca/start` |
| `POST` | `/auth/verify/ca/complete` |
| `POST` | `/auth/verify/session` |
| `GET` | `/auth/verify/session/:token` |
| `POST` | `/auth/verify/session/:token/opened` |
| `POST` | `/auth/verify/approve` |

## Realtime and communications

| Method | Path |
|---|---|
| `GET` | `/auth/livekit-token` |
| `GET` | `/auth/turn-credentials` |
| `POST` | `/auth/call-invite` |

## Internal

| Method | Path |
|---|---|
| `POST` | `/internal/hasura-event` |
| `GET` | `/healthz` |
| `POST` | `/v1/verify` |

`/healthz` and `/v1/verify` belong to the isolated biometric service.
`/v1/verify` must not be exposed through a public ingress.

## Required review matrix

For every endpoint, record:

- authentication and authorization decision;
- session revocation behavior;
- request size and content-type enforcement;
- shared fail-closed rate limit;
- nonce/idempotency/replay behavior where applicable;
- CSRF, OAuth state and postMessage origin binding where applicable;
- upload type validation and safe response headers;
- log redaction and error disclosure;
- deletion, retention and recovery behavior;
- race and dependency-failure behavior.
