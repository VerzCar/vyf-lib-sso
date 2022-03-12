package sso

import (
	"context"
	"github.com/Nerzal/gocloak/v10"
	"github.com/golang-jwt/jwt/v4"
)

type Service interface {
	DecodeAccessToken(ctx context.Context, accessToken string, options ...Option) (*jwt.Token, *Claims, error)
	DefaultRealm() string
	CreateUser(ctx context.Context, email string, password string, options ...Option) (string, error)
	DeleteUser(ctx context.Context, userId string, options ...Option) error
	UserInfo(ctx context.Context, accessToken string, options ...Option) (*UserInfo, error)
	SendVerificationEmail(ctx context.Context, userId string, redirectUri string, options ...Option) error
	Login(ctx context.Context, username string, password string, options ...Option) (*JWT, error)
	Logout(ctx context.Context, refreshToken string, options ...Option) error
}

type service struct {
	sso  gocloak.GoCloak
	opts []Option
}

type Option func(bd *Request)

// NewService creates a new sso service.
// The options don't need to be set but if given
// this options will be used for the upcoming requests to the sso client.
func NewService(
	host string,
	opts ...Option,
) Service {
	sso := gocloak.NewClient(host)

	return &service{
		sso:  sso,
		opts: opts,
	}
}

// DecodeAccessToken of given accessToken and verifies it against the given realm.
// It converts the JWT sub into the custom claim of the go sso type.
// Returns the jwt.Token and the SsoClaims representation if successful, otherwise an error.
func (s *service) DecodeAccessToken(
	ctx context.Context,
	accessToken string,
	options ...Option,
) (
	*jwt.Token,
	*Claims,
	error,
) {
	req := s.applyOptions(options)

	ssoClaims := &Claims{}
	decodedToken, err := s.sso.DecodeAccessTokenCustomClaims(ctx, accessToken, req.realm, ssoClaims)

	return decodedToken, ssoClaims, err
}

// DefaultRealm returns the default realm of this service
// if set on init.
func (s *service) DefaultRealm() string {
	req := &Request{}

	for _, option := range s.opts {
		option(req)
	}
	return req.realm
}

// CreateUser with the given data.
// Returns the created user id if successful, otherwise an error.
func (s *service) CreateUser(
	ctx context.Context,
	email string,
	password string,
	options ...Option,
) (string, error) {
	req := s.applyOptions(options)

	jwtToken, err := s.accessToken(ctx, req)

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
		req.realm,
		user,
	)

	if err != nil {
		return "", err
	}

	return identityId, nil
}

// DeleteUser with the given user id.
// Returns nil if successful, otherwise an error.
func (s *service) DeleteUser(
	ctx context.Context,
	userId string,
	options ...Option,
) error {
	req := s.applyOptions(options)

	jwtToken, err := s.accessToken(ctx, req)

	if err != nil {
		return err
	}

	err = s.sso.DeleteUser(
		ctx,
		jwtToken.AccessToken,
		req.realm,
		userId,
	)

	if err != nil {
		return err
	}

	return nil
}

func (s *service) UserInfo(
	ctx context.Context,
	accessToken string,
	options ...Option,
) (*UserInfo, error) {
	req := s.applyOptions(options)

	goUserInfo, err := s.sso.GetUserInfo(
		ctx,
		accessToken,
		req.realm,
	)

	if err != nil {
		return nil, err
	}

	userInfo := &UserInfo{*goUserInfo}

	return userInfo, nil

}

// SendVerificationEmail send the verification email of the given user id.
// Returns nil if successful, otherwise an error.
// TODO change to the correct endpoint send_verification_email "http://localhost:1010/auth/"
func (s *service) SendVerificationEmail(
	ctx context.Context,
	userId string,
	redirectUri string,
	options ...Option,
) error {
	req := s.applyOptions(options)

	jwtToken, err := s.accessToken(ctx, req)

	if err != nil {
		return err
	}

	emailParams := gocloak.ExecuteActionsEmail{
		UserID:      &userId,
		ClientID:    &req.clientID,
		Lifespan:    nil,
		RedirectURI: &redirectUri,
		Actions:     &[]string{"VERIFY_EMAIL"},
	}

	err = s.sso.ExecuteActionsEmail(
		ctx,
		jwtToken.AccessToken,
		req.realm,
		emailParams,
	)

	if err != nil {
		return err
	}

	return nil
}

func (s *service) Login(
	ctx context.Context,
	username string,
	password string,
	options ...Option,
) (*JWT, error) {
	req := s.applyOptions(options)

	goJwt, err := s.sso.Login(
		ctx,
		req.clientID,
		req.clientSecret,
		req.realm,
		username,
		password,
	)

	if err != nil {
		return nil, err
	}

	ssoJwt := &JWT{*goJwt}

	return ssoJwt, nil
}

func (s *service) Logout(
	ctx context.Context,
	refreshToken string,
	options ...Option,
) error {
	req := s.applyOptions(options)

	err := s.sso.Logout(
		ctx,
		req.clientID,
		req.clientSecret,
		req.realm,
		refreshToken,
	)

	if err != nil {
		return err
	}

	return nil
}

// accessToken gets the access token for the admin login.
// Returns the gocloak.JWT representation if successful, otherwise an error.
func (s *service) accessToken(ctx context.Context, req *Request) (*gocloak.JWT, error) {
	jwtToken, err := s.sso.LoginAdmin(
		ctx,
		req.admin.username,
		req.admin.password,
		req.realm,
	)

	if err != nil {
		return nil, err
	}

	return jwtToken, nil
}

func (s *service) applyOptions(options []Option) *Request {
	req := &Request{}

	// per client options apply first
	for _, option := range s.opts {
		option(req)
	}
	// per request options
	for _, option := range options {
		option(req)
	}
	return req
}
