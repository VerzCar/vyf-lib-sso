package sso

import (
	"fmt"
	"github.com/mitchellh/mapstructure"
)

type config struct {
	Sso struct {
		Realm struct {
			Default string
		}
		Client struct {
			Id     string
			Secret string
		}
		Admin struct {
			Username string
			Password string
		}
	}

	Hosts struct {
		Svc struct {
			Sso string
		}
	}
}

func newConfig(envConfig interface{}) (*config, error) {
	c := &config{}
	if err := unpack(envConfig, c); err != nil {
		return nil, err
	}
	return c, nil
}

func unpack(data interface{}, into interface{}) error {
	d, err := mapstructure.NewDecoder(
		&mapstructure.DecoderConfig{
			Result:      into,
			ErrorUnused: false,
			ZeroFields:  true,
			Squash:      true,
		},
	)
	if err != nil {
		return fmt.Errorf("mapstructure: %s", err.Error())
	}

	return d.Decode(data)
}
