-- name: CreateUser :one
INSERT INTO "user" (id, name, email, email_verified, image, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM "user" WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM "user" WHERE email = $1;

-- name: UpdateUser :one
UPDATE "user"
SET name = COALESCE($2, name),
    email = COALESCE($3, email),
    email_verified = COALESCE($4, email_verified),
    image = COALESCE($5, image),
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: UpdateUserEmail :one
UPDATE "user"
SET email = $2, email_verified = $3, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: VerifyUserEmail :one
UPDATE "user"
SET email_verified = TRUE, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: DeleteUser :exec
DELETE FROM "user" WHERE id = $1;

-- name: ListUsers :many
SELECT * FROM "user"
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountUsers :one
SELECT COUNT(*) FROM "user";
