package oauth

import (
	"fmt"

	"github.com/kainos-it-com/kainos-auth/core"
)

// Google returns a Google OAuth provider
func Google(clientID, clientSecret, redirectURL string) *Provider {
	return &Provider{
		ID:           "google",
		Name:         "Google",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		UserInfoURL:  "https://www.googleapis.com/oauth2/v2/userinfo",
		Scopes:       []string{"openid", "email", "profile"},
		RedirectURL:  redirectURL,
		MapProfile: func(raw map[string]interface{}) *core.OAuthProfile {
			profile := &core.OAuthProfile{Raw: raw}
			if id, ok := raw["id"].(string); ok {
				profile.ID = id
			}
			if email, ok := raw["email"].(string); ok {
				profile.Email = email
			}
			if name, ok := raw["name"].(string); ok {
				profile.Name = name
			}
			if picture, ok := raw["picture"].(string); ok {
				profile.Image = &picture
			}
			if verified, ok := raw["verified_email"].(bool); ok {
				profile.EmailVerified = verified
			}
			return profile
		},
	}
}

// GitHub returns a GitHub OAuth provider
func GitHub(clientID, clientSecret, redirectURL string) *Provider {
	return &Provider{
		ID:           "github",
		Name:         "GitHub",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      "https://github.com/login/oauth/authorize",
		TokenURL:     "https://github.com/login/oauth/access_token",
		UserInfoURL:  "https://api.github.com/user",
		Scopes:       []string{"read:user", "user:email"},
		RedirectURL:  redirectURL,
	}
}

// Discord returns a Discord OAuth provider
func Discord(clientID, clientSecret, redirectURL string) *Provider {
	return &Provider{
		ID:           "discord",
		Name:         "Discord",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      "https://discord.com/api/oauth2/authorize",
		TokenURL:     "https://discord.com/api/oauth2/token",
		UserInfoURL:  "https://discord.com/api/users/@me",
		Scopes:       []string{"identify", "email"},
		RedirectURL:  redirectURL,
		MapProfile: func(raw map[string]interface{}) *core.OAuthProfile {
			profile := &core.OAuthProfile{Raw: raw}
			if id, ok := raw["id"].(string); ok {
				profile.ID = id
			}
			if email, ok := raw["email"].(string); ok {
				profile.Email = email
			}
			if username, ok := raw["username"].(string); ok {
				profile.Name = username
			}
			if avatar, ok := raw["avatar"].(string); ok {
				if id, ok := raw["id"].(string); ok {
					avatarURL := fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", id, avatar)
					profile.Image = &avatarURL
				}
			}
			if verified, ok := raw["verified"].(bool); ok {
				profile.EmailVerified = verified
			}
			return profile
		},
	}
}

// Microsoft returns a Microsoft OAuth provider
func Microsoft(clientID, clientSecret, redirectURL string) *Provider {
	return &Provider{
		ID:           "microsoft",
		Name:         "Microsoft",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		UserInfoURL:  "https://graph.microsoft.com/v1.0/me",
		Scopes:       []string{"openid", "email", "profile", "User.Read"},
		RedirectURL:  redirectURL,
		MapProfile: func(raw map[string]interface{}) *core.OAuthProfile {
			profile := &core.OAuthProfile{Raw: raw}
			if id, ok := raw["id"].(string); ok {
				profile.ID = id
			}
			if email, ok := raw["mail"].(string); ok {
				profile.Email = email
			} else if upn, ok := raw["userPrincipalName"].(string); ok {
				profile.Email = upn
			}
			if name, ok := raw["displayName"].(string); ok {
				profile.Name = name
			}
			profile.EmailVerified = true
			return profile
		},
	}
}

// Apple returns an Apple OAuth provider
func Apple(clientID, clientSecret, redirectURL string) *Provider {
	return &Provider{
		ID:           "apple",
		Name:         "Apple",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      "https://appleid.apple.com/auth/authorize",
		TokenURL:     "https://appleid.apple.com/auth/token",
		UserInfoURL:  "",
		Scopes:       []string{"name", "email"},
		RedirectURL:  redirectURL,
	}
}
