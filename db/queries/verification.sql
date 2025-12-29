-- name: CreateVerification :one
INSERT INTO "verification" (id, identifier, value, expires_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, NOW(), NOW())
RETURNING *;

-- name: GetVerificationByID :one
SELECT * FROM "verification" WHERE id = $1;

-- name: GetVerificationByIdentifier :one
SELECT * FROM "verification"
WHERE identifier = $1 AND expires_at > NOW()
ORDER BY created_at DESC
LIMIT 1;

-- name: GetVerificationByValue :one
SELECT * FROM "verification"
WHERE value = $1 AND expires_at > NOW();

-- name: ValidateVerification :one
SELECT * FROM "verification"
WHERE identifier = $1 AND value = $2 AND expires_at > NOW();

-- name: DeleteVerification :exec
DELETE FROM "verification" WHERE id = $1;

-- name: DeleteVerificationByIdentifier :exec
DELETE FROM "verification" WHERE identifier = $1;

-- name: DeleteExpiredVerifications :exec
DELETE FROM "verification" WHERE expires_at < NOW();

-- name: DeleteUserVerifications :exec
DELETE FROM "verification" WHERE identifier = $1;
