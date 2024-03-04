package provider

import (
	"context"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const (
	defaultDescopeAPIBase = "https://api.descope.com"
)

type descopeProvider struct {
	*oauth2.Config
	APIHost string
}

type descopeUser struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	PhoneNumber   string `json:"phone_number"`
	PhoneVerified bool   `json:"phone_verified"`
	FamilyName    string `json:"family_name"`
	GivenName     string `json:"given_name"`
	Picture       string `json:"picture"`
}

func (p descopeProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return p.Exchange(context.Background(), code)
}

func (p descopeProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u descopeUser

	if err := makeRequest(ctx, tok, p.Config, p.APIHost+"/oauth2/v1/userinfo", &u); err != nil {
		return nil, err
	}

	data := &UserProvidedData{}

	if u.Email != "" {
		data.Emails = []Email{
			{
				Email:    u.Email,
				Verified: u.EmailVerified,
				Primary:  true,
			},
		}
	}

	data.Metadata = &Claims{
		Issuer:        p.APIHost,
		Subject:       u.Sub,
		Name:          u.Name,
		ProviderId:    u.Sub,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		FamilyName:    u.FamilyName,
		GivenName:     u.GivenName,
		Phone:         u.PhoneNumber,
		PhoneVerified: u.PhoneVerified,
		Picture:       u.Picture,
	}
	return data, nil
}

func NewDescopeProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	oauthScopes := []string{
		"openid",
		"profile",
		"email",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	baseURL := chooseHost(ext.URL, defaultDescopeAPIBase)
	var apiHost string

	// If Issuer URL contains custom Application ID
	if strings.Count(baseURL, "/") > 2 {
		// Extract Application ID
		appId := strings.Split(baseURL, "/")[3]
		apiHost = chooseHost("", defaultDescopeAPIBase) + "/" + appId
	} else {
		// Use the default API base without Application ID
		apiHost = chooseHost("", defaultDescopeAPIBase)
	}

	return &descopeProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthStyle: oauth2.AuthStyleInParams,
				AuthURL:   apiHost + "/oauth2/v1/authorize",
				TokenURL:  apiHost + "/oauth2/v1/token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		APIHost: apiHost,
	}, nil
}
