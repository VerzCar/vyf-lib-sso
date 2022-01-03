package sso

import (
	"context"
	"github.com/Nerzal/gocloak/v10"
	"github.com/golang-jwt/jwt/v4"
)

type Service interface {
	DecodeAccessToken(ctx context.Context, accessToken string, realm string) (*jwt.Token, *SsoClaims, error)
	DefaultRealm() string
	CreateUser(ctx context.Context, email string, password string) (string, error)
	DeleteUser(ctx context.Context, userId string) error
	SendVerificationEmail(ctx context.Context, userId string) error
}

type service struct {
	sso    gocloak.GoCloak
	config *config
}

// NewService creates a new sso service.
// The given configuration must have the at least the values
// of the sso.config otherwise an error will be thrown.
func NewService(
	envConfig interface{},
) (Service, error) {
	config, err := newConfig(envConfig)

	if err != nil {
		return nil, err
	}

	sso := gocloak.NewClient(config.Hosts.Svc.Sso)

	return &service{
		sso:    sso,
		config: config,
	}, nil
}

// DecodeAccessToken of given accessToken and verifies it against the given realm.
// It converts the JWT sub into the custom claim of the go sso type.
// Returns the jwt.Token and the SsoClaims representation if successful, otherwise an error.
func (s *service) DecodeAccessToken(ctx context.Context, accessToken string, realm string) (
	*jwt.Token,
	*SsoClaims,
	error,
) {

	ssoClaims := &SsoClaims{}
	decodedToken, err := s.sso.DecodeAccessTokenCustomClaims(ctx, accessToken, realm, ssoClaims)

	return decodedToken, ssoClaims, err
}

// DefaultRealm returns the default realm of this service
func (s *service) DefaultRealm() string {
	return s.config.Sso.Realm.Default
}

// CreateUser with the given data.
// Returns the created user id if successful, otherwise an error.
func (s *service) CreateUser(ctx context.Context, email string, password string) (string, error) {
	realm := s.config.Sso.Realm.Default

	jwtToken, err := s.accessToken(ctx)

	if err != nil {
		return "", err
	}

	user := gocloak.User{
		Username: &email,
		Email:    &email,
		Enabled:  gocloak.BoolP(true),
		Credentials: &[]gocloak.CredentialRepresentation{
			{
				Type:      gocloak.StringP("password"),
				Value:     &password,
				Temporary: gocloak.BoolP(false),
			},
		},
		RequiredActions: &[]string{"VERIFY_EMAIL"},
	}

	identityId, err := s.sso.CreateUser(
		ctx,
		jwtToken.AccessToken,
		realm,
		user,
	)

	if err != nil {
		return "", err
	}

	return identityId, nil
}

// DeleteUser with the given user id.
// Returns nil if successful, otherwise an error.
func (s *service) DeleteUser(ctx context.Context, userId string) error {
	realm := s.config.Sso.Realm.Default

	jwtToken, err := s.accessToken(ctx)

	if err != nil {
		return err
	}

	err = s.sso.DeleteUser(
		ctx,
		jwtToken.AccessToken,
		realm,
		userId,
	)

	if err != nil {
		return err
	}

	return nil
}

// SendVerificationEmail send the verification email of the given user id.
// Returns nil if successful, otherwise an error.
// TODO change to the correct endpoint send_verification_email
func (s *service) SendVerificationEmail(ctx context.Context, userId string) error {
	realm := s.config.Sso.Realm.Default

	jwtToken, err := s.accessToken(ctx)

	if err != nil {
		return err
	}

	emailParams := gocloak.ExecuteActionsEmail{
		UserID:      &userId,
		ClientID:    &s.config.Sso.Client.Id,
		Lifespan:    nil,
		RedirectURI: gocloak.StringP("http://localhost:1010/auth/"),
		Actions:     &[]string{"VERIFY_EMAIL"},
	}

	err = s.sso.ExecuteActionsEmail(
		ctx,
		jwtToken.AccessToken,
		realm,
		emailParams,
	)

	if err != nil {
		return err
	}

	return nil
}

// accessToken gets the access token for the admin login.
// Returns the gocloak.JWT representation if successful, otherwise an error.
func (s *service) accessToken(ctx context.Context) (*gocloak.JWT, error) {
	realm := s.config.Sso.Realm.Default

	jwtToken, err := s.sso.LoginAdmin(
		ctx,
		s.config.Sso.Admin.Username,
		s.config.Sso.Admin.Password,
		realm,
	)

	if err != nil {
		return nil, err
	}

	return jwtToken, nil
}
