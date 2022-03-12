package sso

// Realm sets the realm
func Realm(name string) Option {
	return func(req *Request) {
		req.realm = name
	}
}

// ClientId sets the client id
func ClientId(clientId string) Option {
	return func(req *Request) {
		req.clientID = clientId
	}
}

// ClientSecret sets the client secret
func ClientSecret(clientSecret string) Option {
	return func(req *Request) {
		req.clientSecret = clientSecret
	}
}

// AdminCredentials sets the credentials for the admin
func AdminCredentials(username, password string) Option {
	return func(req *Request) {
		req.admin.username = username
		req.admin.password = password
	}
}
