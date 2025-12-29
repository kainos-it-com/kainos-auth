-- name: CreateAccount :one
INSERT INTO "account" (
    id, user_id, account_id, provider_id, access_token, refresh_token,
    access_token_expires_at, refresh_token_expires_at, scope, id_token, password,
    created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
RETURNING *;

-- name: GetAccountByID :one
SELECT * FROM "account" WHERE id = $1;

-- name: GetAccountByProvider :one
SELECT * FROM "account"
WHERE provider_id = $1 AND account_id = $2;

-- name: GetUserCredentialAccount :one
SELECT * FROM "account"
WHERE user_id = $1 AND provider_id = 'credential';

-- name: ListUserAccounts :many
SELECT * FROM "account"
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: UpdateAccountTokens :one
UPDATE "account"
SET access_token = $2,
    refresh_token = $3,
    access_token_expires_at = $4,
    refresh_token_expires_at = $5,
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: UpdateAccountPassword :one
UPDATE "account"
SET password = $2, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: SetUserPassword :one
UPDATE "account"
SET password = $2, updated_at = NOW()
WHERE user_id = $1 AND provider_id = 'credential'
RETURNING *;

-- name: LinkAccount :one
INSERT INTO "account" (
    id, user_id, account_id, provider_id, access_token, refresh_token,
    access_token_expires_at, refresh_token_expires_at, scope, id_token,
    created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
RETURNING *;

-- name: UnlinkAccount :exec
DELETE FROM "account"
WHERE user_id = $1 AND provider_id = $2;

-- name: DeleteAccount :exec
DELETE FROM "account" WHERE id = $1;

-- name: DeleteUserAccounts :exec
DELETE FROM "account" WHERE user_id = $1;

-- name: CountUserAccounts :one
SELECT COUNT(*) FROM "account" WHERE user_id = $1;
