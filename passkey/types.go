package passkey

import "time"

// Passkey represents a stored passkey
type Passkey struct {
	ID           string
	UserID       string
	Name         string
	CredentialID string
	PublicKey    []byte
	Counter      uint32
	DeviceType   string // "platform" or "cross-platform"
	BackedUp     bool
	Transports   []string
	AAGUID       string
	CreatedAt    time.Time
}

// RegistrationOptions contains options for passkey registration
type RegistrationOptions struct {
	Challenge              string                  `json:"challenge"`
	RP                     RelyingParty            `json:"rp"`
	User                   UserEntity              `json:"user"`
	PubKeyCredParams       []PubKeyCredParam       `json:"pubKeyCredParams"`
	Timeout                int64                   `json:"timeout"`
	Attestation            string                  `json:"attestation"`
	AuthenticatorSelection *AuthenticatorSelection `json:"authenticatorSelection,omitempty"`
}

// RelyingParty represents the relying party
type RelyingParty struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// UserEntity represents the user for WebAuthn
type UserEntity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// PubKeyCredParam represents a public key credential parameter
type PubKeyCredParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

// AuthenticatorSelection specifies authenticator requirements
type AuthenticatorSelection struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	ResidentKey             string `json:"residentKey,omitempty"`
	UserVerification        string `json:"userVerification,omitempty"`
}

// AuthenticationOptions contains options for passkey authentication
type AuthenticationOptions struct {
	Challenge        string            `json:"challenge"`
	Timeout          int64             `json:"timeout"`
	RPID             string            `json:"rpId"`
	AllowCredentials []AllowCredential `json:"allowCredentials,omitempty"`
	UserVerification string            `json:"userVerification"`
}

// AllowCredential represents an allowed credential
type AllowCredential struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

// FinishRegistrationInput contains the registration response from the client
type FinishRegistrationInput struct {
	UserID       string
	Name         string
	CredentialID string
	PublicKey    []byte
	Counter      uint32
	DeviceType   string
	BackedUp     bool
	Transports   []string
	AAGUID       string
}

// FinishAuthenticationInput contains the authentication response from the client
type FinishAuthenticationInput struct {
	CredentialID string
	AuthData     []byte
	ClientData   []byte
	Signature    []byte
	UserHandle   string
	IPAddress    *string
	UserAgent    *string
}
