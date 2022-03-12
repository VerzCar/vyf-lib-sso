package sso

import (
	"github.com/Nerzal/gocloak/v10"
	"github.com/golang-jwt/jwt/v4"
)

type identityProvider struct {
	realm        string
	clientID     string
	clientSecret string
}

type realmAdmin struct {
	username string
	password string
}

type Request struct {
	identityProvider
	admin realmAdmin
}

type Claims struct {
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	MiddleName        string `json:"middle_name,omitempty"`
	Nickname          string `json:"nickname,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	UpdatedAt         int    `json:"updated_at,omitempty"`
	jwt.RegisteredClaims
}

type UserInfo struct {
	gocloak.UserInfo
}

type JWT struct {
	gocloak.JWT
}
