-- name: CreateSession :one
INSERT INTO "session" (id, user_id, token, expires_at, ip_address, user_agent, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
RETURNING *;

-- name: GetSessionByID :one
SELECT * FROM "session" WHERE id = $1;

-- name: GetSessionByToken :one
SELECT * FROM "session" WHERE token = $1;

-- name: GetSessionWithUser :one
SELECT 
    s.*,
    u.id AS user_id,
    u.name AS user_name,
    u.email AS user_email,
    u.email_verified AS user_email_verified,
    u.image AS user_image
FROM "session" s
JOIN "user" u ON s.user_id = u.id
WHERE s.token = $1 AND s.expires_at > NOW();

-- name: ListUserSessions :many
SELECT * FROM "session"
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: ListActiveSessions :many
SELECT * FROM "session"
WHERE user_id = $1 AND expires_at > NOW()
ORDER BY created_at DESC;

-- name: UpdateSessionExpiry :one
UPDATE "session"
SET expires_at = $2, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: RevokeSession :exec
DELETE FROM "session" WHERE id = $1;

-- name: RevokeSessionByToken :exec
DELETE FROM "session" WHERE token = $1;

-- name: RevokeUserSessions :exec
DELETE FROM "session" WHERE user_id = $1;

-- name: RevokeOtherSessions :exec
DELETE FROM "session" WHERE user_id = $1 AND id != $2;

-- name: DeleteExpiredSessions :exec
DELETE FROM "session" WHERE expires_at < NOW();

-- name: CountUserSessions :one
SELECT COUNT(*) FROM "session" WHERE user_id = $1 AND expires_at > NOW();
