package provider

import (
	"fmt"
	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"time"
)

// TODO: This is completely untested code, written from route theory

import (
	"context"
	"encoding/json"
	coreos "github.com/coreos/go-oidc/v3/oidc"
)

// auth0Provider represents the details needed to integrate with Auth0 via OIDC.
type auth0Provider struct {
	*oauth2.Config
	Provider *coreos.Provider
	Domain   string
}

// NewAuth0Provider creates a new Auth0Provider instance with the necessary details.
func NewAuth0Provider(ctx context.Context, ext conf.Auth0ProviderConfiguration) (OAuthProvider, error) {
	provider, err := coreos.NewProvider(
		ctx,
		"https://"+ext.Domain+"/",
	)
	if err != nil {
		return nil, err
	}

	return &auth0Provider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.ClientSecret,
			RedirectURL:  ext.RedirectURI,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{coreos.ScopeOpenID, "profile"},
		},
		Provider: provider,
		Domain:   ext.Domain,
	}, nil
}

func (p *auth0Provider) GetOAuthToken(code string) (token *oauth2.Token, err error) {
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {p.ClientID},
		"client_secret": {p.ClientSecret},
		"code":          {code},
		"redirect_uri":  {p.RedirectURL},
	}

	var resp *http.Response
	if resp, err = http.PostForm(fmt.Sprintf("https://%s/oauth/token", p.Domain), formData); err != nil {
		return
	}
	defer resp.Body.Close()

	var body []byte
	if body, err = io.ReadAll(resp.Body); err != nil {
		return
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"` // This is provided in seconds
		RefreshToken string `json:"refresh_token,omitempty"`
		IDToken      string `json:"id_token,omitempty"`
	}

	if err = json.Unmarshal(body, &tokenResp); err != nil {
		return
	}

	// Calculate the absolute expiry time from the current time and the expires_in duration
	expiryTime := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	// Construct the oauth2.Token using the response data
	token = &oauth2.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		Expiry:      expiryTime,
		// Optionally include the refresh token and ID token if needed
		RefreshToken: tokenResp.RefreshToken,
	}

	token = token.WithExtra(map[string]interface{}{
		"id_token": tokenResp.IDToken,
	})
	return
}

// GetLoginURL generates the login URL to redirect the user to the Auth0 login page.
func (p *auth0Provider) GetLoginURL(state string) string {
	var scope = "openid email profile" // Customize based on your needs
	var responseType = "code"

	u := fmt.Sprintf("https://%s/authorize?response_type=%s&client_id=%s&redirect_uri=%s&scope=%s&state=%s",
		p.Domain, url.QueryEscape(responseType), url.QueryEscape(p.ClientID),
		url.QueryEscape(p.RedirectURL), url.QueryEscape(scope), url.QueryEscape(state))

	return u
}

// GetUserData Populate and return the metadata information
func (p *auth0Provider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	userInfo, err := p.GetUserInfo(ctx, tok.AccessToken)
	if err != nil {
		return nil, err
	}

	// Assuming userInfo is a map[string]interface{} with data from Auth0
	var emails []Email
	if email, ok := userInfo["email"].(string); ok {
		// TODO: Verify field for primary email if it exists
		emails = append(emails, Email{Email: email, Verified: userInfo["email_verified"].(bool), Primary: true})
	}

	// TODO: Check/verify these fields successfully map from auth0
	// Populate metadata from userInfo
	metadata := &Claims{
		Issuer:            userInfo["iss"].(string),
		Subject:           userInfo["sub"].(string),
		Aud:               userInfo["aud"].(string),
		Iat:               userInfo["iat"].(float64),
		Exp:               userInfo["exp"].(float64),
		Name:              userInfo["name"].(string),
		FamilyName:        userInfo["family_name"].(string),
		GivenName:         userInfo["given_name"].(string),
		MiddleName:        userInfo["middle_name"].(string),
		NickName:          userInfo["nickname"].(string),
		PreferredUsername: userInfo["preferred_username"].(string),
		Profile:           userInfo["profile"].(string),
		Picture:           userInfo["picture"].(string),
		Website:           userInfo["website"].(string),
		Gender:            userInfo["gender"].(string),
		Birthdate:         userInfo["birthdate"].(string),
		ZoneInfo:          userInfo["zoneinfo"].(string),
		Locale:            userInfo["locale"].(string),
		UpdatedAt:         userInfo["updated_at"].(string),
		Email:             userInfo["email"].(string),
		EmailVerified:     userInfo["email_verified"].(bool),
		Phone:             userInfo["phone_number"].(string),
		PhoneVerified:     userInfo["phone_verified"].(bool),
		AvatarURL:         userInfo["avatar_url"].(string),
	}

	return &UserProvidedData{
		Emails:   emails,
		Metadata: metadata,
	}, nil
}

// GetUserInfo retrieves the user information from Auth0 using the access token.
func (p *auth0Provider) GetUserInfo(ctx context.Context, accessToken string) (userInfo map[string]interface{}, err error) {
	client := &http.Client{}
	var req *http.Request
	if req, err = http.NewRequest("GET", fmt.Sprintf("https://%s/userinfo", p.Domain), nil); err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	var resp *http.Response
	if resp, err = client.Do(req); err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			// Innocuous
		}
	}(resp.Body)

	var body []byte
	if body, err = io.ReadAll(resp.Body); err != nil {
		return nil, err
	}

	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}

	return userInfo, nil
}
