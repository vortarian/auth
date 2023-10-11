package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/storage"
	"github.com/supabase/gotrue/internal/utilities"
	"github.com/xeipuuv/gojsonschema"
)

type HookEvent string

const (
	headerHookSignature = "x-webhook-signature"
	defaultHookRetries  = 3
	gotrueIssuer        = "gotrue"
	// TODO (Joel): Properly substitute this
	authHookIssuer   = "auth"
	ValidateEvent    = "validate"
	SignupEvent      = "signup"
	EmailChangeEvent = "email_change"
	LoginEvent       = "login"
)

const (
	webhookSignatureHeader = "webhook-signature"
	webhookTimestampHeader = "webhook-timestamp"
	webhookIDHeader        = "webhook-id"
)

// ExtensibilityPoints
const (
	CustomSMSExtensibilityPoint = "custom-sms-provider"
)

var defaultTimeout = time.Second * 5

type webhookClaims struct {
	jwt.StandardClaims
	SHA256 string `json:"sha256"`
}

type Webhook struct {
	*conf.WebhookConfig

	jwtSecret string
	claims    jwt.Claims
	payload   []byte
}

type WebhookResponse struct {
	AppMetaData  map[string]interface{} `json:"app_metadata,omitempty"`
	UserMetaData map[string]interface{} `json:"user_metadata,omitempty"`
}

// Duplicate of Webhook, should eventually modify the fields passed
type AuthHook struct {
	*conf.WebhookConfig
	// Decide what should go here
	jwtSecret string
	claims    jwt.Claims
}

func setWebhookHeaders(req *http.Request, hookID uuid.UUID, timestamp int64) {
	req.Header.Set("webhook-id", hookID.String())
	req.Header.Set("webhook-timestamp", fmt.Sprintf("%v", timestamp))
	// req.Header.Set("webhook-signature", "<generate-and-pass-this-in>")
}

func generateHookCompliantTimestamp(timestamp time.Time) string {
	// Timeformat taken from Webhooks standard
	timeFormat := "2022-11-03T20:26:10.344522Z"
	formattedTime := timestamp.Format(timeFormat)
	return formattedTime
}

func (a *AuthHook) trigger() (io.ReadCloser, error) {
	timeout := defaultTimeout
	if a.TimeoutSec > 0 {
		timeout = time.Duration(a.TimeoutSec) * time.Second
	}

	if a.Retries == 0 {
		a.Retries = defaultHookRetries
	}
	hookID := uuid.Must(uuid.NewV4())
	timestamp := time.Now().Unix()
	signature, err := a.generateSignature()
	if err != nil {
		return nil, err
	}

	hooklog := logrus.WithFields(logrus.Fields{
		"component":   "webhook",
		"uri":         a.URL,
		"instance_id": uuid.Nil.String(),
		"hook_id":     hookID,
		"timestamp":   timestamp,
		"signature":   signature,
	})
	client := http.Client{
		Timeout: timeout,
	}
	signedPayload, jwtErr := a.generateBody()
	if jwtErr != nil {
		return nil, jwtErr
	}

	jsonString := struct {
		JWT string `json:"jwt"`
	}{
		JWT: signedPayload,
	}

	// Marshal the JSON object to JSON format
	requestLoad, err := json.Marshal(jsonString)
	if err != nil {
		return nil, err
	}
	for i := 0; i < a.Retries; i++ {
		hooklog = hooklog.WithField("attempt", i+1)
		hooklog.Info("Starting to perform signup hook request")

		req, err := http.NewRequest(http.MethodPost, a.URL, bytes.NewBuffer(requestLoad))
		if err != nil {
			return nil, internalServerError("Failed to make request object").WithInternalError(err)
		}

		setWebhookHeaders(req, hookID, timestamp)

		req.Header.Set("Content-Type", "application/json")

		watcher, req := watchForConnection(req)

		start := time.Now()
		rsp, err := client.Do(req)
		if err != nil {
			if terr, ok := err.(net.Error); ok && terr.Timeout() {
				// timed out - try again?
				if i == a.Retries-1 {
					closeBody(rsp)
					return nil, httpError(http.StatusGatewayTimeout, "Failed to perform webhook in time frame (%v seconds)", timeout.Seconds())
				}
				hooklog.Info("Request timed out")
				continue
			} else if watcher.gotConn {
				closeBody(rsp)
				return nil, internalServerError("Failed to trigger webhook to %s", a.URL).WithInternalError(err)
			} else {
				closeBody(rsp)
				return nil, httpError(http.StatusBadGateway, "Failed to connect to %s", a.URL)
			}
		}
		dur := time.Since(start)
		rspLog := hooklog.WithFields(logrus.Fields{
			"status_code": rsp.StatusCode,
			"dur":         dur.Nanoseconds(),
		})
		switch rsp.StatusCode {
		case http.StatusOK, http.StatusNoContent, http.StatusAccepted:
			rspLog.Infof("Finished processing webhook in %s", dur)
			var body io.ReadCloser
			if rsp.ContentLength > 0 {
				body = rsp.Body
			}
			fmt.Printf("%v", rsp)
			fmt.Println(body)
			return body, nil
		default:
			rspLog.Infof("Bad response for webhook %d in %s", rsp.StatusCode, dur)
		}
	}

	hooklog.Infof("Failed to process webhook for %s after %d attempts", a.URL, a.Retries)
	return nil, unprocessableEntityError("Failed to handle signup webhook")
}
func (a *AuthHook) generateBody() (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, a.claims)
	tokenString, err := token.SignedString([]byte(a.jwtSecret))
	if err != nil {
		return "", internalServerError("Failed build signing string").WithInternalError(err)
	}
	return tokenString, nil
}

func (a *AuthHook) generateSignature() (string, error) {
	// TODO: change this to {msg_id}.{timestamp}.{payload}.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, a.claims)
	tokenString, err := token.SignedString([]byte(a.jwtSecret))
	if err != nil {
		return "", internalServerError("Failed build signing string").WithInternalError(err)
	}
	return tokenString, nil
}

func (w *Webhook) trigger() (io.ReadCloser, error) {
	timeout := defaultTimeout
	if w.TimeoutSec > 0 {
		timeout = time.Duration(w.TimeoutSec) * time.Second
	}

	if w.Retries == 0 {
		w.Retries = defaultHookRetries
	}

	hooklog := logrus.WithFields(logrus.Fields{
		"component":   "webhook",
		"url":         w.URL,
		"signed":      w.jwtSecret != "",
		"instance_id": uuid.Nil.String(),
	})
	client := http.Client{
		Timeout: timeout,
	}

	for i := 0; i < w.Retries; i++ {
		hooklog = hooklog.WithField("attempt", i+1)
		hooklog.Info("Starting to perform signup hook request")

		req, err := http.NewRequest(http.MethodPost, w.URL, bytes.NewBuffer(w.payload))
		if err != nil {
			return nil, internalServerError("Failed to make request object").WithInternalError(err)
		}
		req.Header.Set("Content-Type", "application/json")
		watcher, req := watchForConnection(req)

		if w.jwtSecret != "" {
			header, jwtErr := w.generateSignature()
			if jwtErr != nil {
				return nil, jwtErr
			}
			req.Header.Set(headerHookSignature, header)
		}

		start := time.Now()
		rsp, err := client.Do(req)
		if err != nil {
			if terr, ok := err.(net.Error); ok && terr.Timeout() {
				// timed out - try again?
				if i == w.Retries-1 {
					closeBody(rsp)
					return nil, httpError(http.StatusGatewayTimeout, "Failed to perform webhook in time frame (%v seconds)", timeout.Seconds())
				}
				hooklog.Info("Request timed out")
				continue
			} else if watcher.gotConn {
				closeBody(rsp)
				return nil, internalServerError("Failed to trigger webhook to %s", w.URL).WithInternalError(err)
			} else {
				closeBody(rsp)
				return nil, httpError(http.StatusBadGateway, "Failed to connect to %s", w.URL)
			}
		}
		dur := time.Since(start)
		rspLog := hooklog.WithFields(logrus.Fields{
			"status_code": rsp.StatusCode,
			"dur":         dur.Nanoseconds(),
		})
		switch rsp.StatusCode {
		case http.StatusOK, http.StatusNoContent, http.StatusAccepted:
			rspLog.Infof("Finished processing webhook in %s", dur)
			var body io.ReadCloser
			if rsp.ContentLength > 0 {
				body = rsp.Body
			}
			return body, nil
		default:
			rspLog.Infof("Bad response for webhook %d in %s", rsp.StatusCode, dur)
		}
	}

	hooklog.Infof("Failed to process webhook for %s after %d attempts", w.URL, w.Retries)
	return nil, unprocessableEntityError("Failed to handle signup webhook")
}

func (w *Webhook) generateSignature() (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, w.claims)
	tokenString, err := token.SignedString([]byte(w.jwtSecret))
	if err != nil {
		return "", internalServerError("Failed build signing string").WithInternalError(err)
	}
	return tokenString, nil
}

func closeBody(rsp *http.Response) {
	if rsp != nil && rsp.Body != nil {
		if err := rsp.Body.Close(); err != nil {
			logrus.WithError(err).Warn("body close in hooks failed")
		}
	}
}

func triggerAuthHook(ctx context.Context, conn *storage.Connection, hookConfig models.HookConfig, user *models.User, config *conf.GlobalConfiguration, metadata map[string]interface{}) (map[string]interface{}, error) {
	inp, err := EncodeAndValidateInput(user, hookConfig, metadata)
	if err != nil {
		return nil, err
	}

	// TODO: substitute with a custom claims interface
	claims := jwt.MapClaims{
		"IssuedAt": time.Now().Unix(),
		"Subject":  uuid.Nil.String(),
		"Issuer":   authHookIssuer,
		"Type":     hookConfig.EventName,
		// TODO: For readbility, kind of duplicate of issuedAt. Check if we need this
		"Timestamp": generateHookCompliantTimestamp(time.Now().UTC()),
		"Data":      inp,
	}

	a := AuthHook{
		WebhookConfig: &config.Webhook,
		// TODO: Add logic to support JWT secret selection
		jwtSecret: hookConfig.Secret[0],
		claims:    claims,
	}

	// Works out because this is a http hook - eventually needs to change
	a.URL = hookConfig.URI

	body, err := a.trigger()
	if body != nil {
		defer utilities.SafeClose(body)
	}

	if err == nil && body != nil {
		resp, err := DecodeAndValidateResponse(hookConfig, body)
		if err != nil {
			// TODO: Figure out if there's a way to not lose typing here
			return resp.(map[string]interface{}), err
		}
		return resp.(map[string]interface{}), nil
	}
	if err != nil {
		return nil, err
	}
	return nil, err
}

// Deprecate this
func triggerEventHooks(ctx context.Context, conn *storage.Connection, event HookEvent, user *models.User, config *conf.GlobalConfiguration) error {
	if config.Webhook.URL != "" {
		hookURL, err := url.Parse(config.Webhook.URL)
		if err != nil {
			return errors.Wrapf(err, "Failed to parse Webhook URL")
		}
		if !config.Webhook.HasEvent(string(event)) {
			return nil
		}
		return triggerHook(ctx, hookURL, config.Webhook.Secret, conn, event, user, config)
	}

	fun := getFunctionHooks(ctx)
	if fun == nil {
		return nil
	}

	for _, eventHookURL := range fun[string(event)] {
		hookURL, err := url.Parse(eventHookURL)
		if err != nil {
			return errors.Wrapf(err, "Failed to parse Event Function Hook URL")
		}
		err = triggerHook(ctx, hookURL, config.JWT.Secret, conn, event, user, config)
		if err != nil {
			return err
		}
	}
	return nil
}

func triggerHook(ctx context.Context, hookURL *url.URL, secret string, conn *storage.Connection, event HookEvent, user *models.User, config *conf.GlobalConfiguration) error {
	if !hookURL.IsAbs() {
		siteURL, err := url.Parse(config.SiteURL)
		if err != nil {
			return errors.Wrapf(err, "Failed to parse Site URL")
		}
		hookURL.Scheme = siteURL.Scheme
		hookURL.Host = siteURL.Host
		hookURL.User = siteURL.User
	}

	payload := struct {
		Event      HookEvent    `json:"event"`
		InstanceID uuid.UUID    `json:"instance_id,omitempty"`
		User       *models.User `json:"user"`
	}{
		Event:      event,
		InstanceID: uuid.Nil,
		User:       user,
	}
	data, err := json.Marshal(&payload)
	if err != nil {
		return internalServerError("Failed to serialize the data for signup webhook").WithInternalError(err)
	}

	sha, err := checksum(data)
	if err != nil {
		return internalServerError("Failed to checksum the data for signup webhook").WithInternalError(err)
	}

	claims := webhookClaims{
		StandardClaims: jwt.StandardClaims{
			IssuedAt: time.Now().Unix(),
			Subject:  uuid.Nil.String(),
			Issuer:   gotrueIssuer,
		},
		SHA256: sha,
	}

	w := Webhook{
		WebhookConfig: &config.Webhook,
		jwtSecret:     secret,
		claims:        claims,
		payload:       data,
	}

	w.URL = hookURL.String()

	body, err := w.trigger()
	if body != nil {
		defer utilities.SafeClose(body)
	}
	if err == nil && body != nil {
		webhookRsp := &WebhookResponse{}
		decoder := json.NewDecoder(body)
		if err = decoder.Decode(webhookRsp); err != nil {
			return webhookResponseError(err.Error()).WithInternalError(err)
		}

		return conn.Transaction(func(tx *storage.Connection) error {
			if webhookRsp.UserMetaData != nil {
				user.UserMetaData = nil
				if terr := user.UpdateUserMetaData(tx, webhookRsp.UserMetaData); terr != nil {
					return terr
				}
			}
			if webhookRsp.AppMetaData != nil {
				user.AppMetaData = nil
				if terr := user.UpdateAppMetaData(tx, webhookRsp.AppMetaData); terr != nil {
					return terr
				}
			}
			return nil
		})
	}
	return err
}

func watchForConnection(req *http.Request) (*connectionWatcher, *http.Request) {
	w := new(connectionWatcher)
	t := &httptrace.ClientTrace{
		GotConn: w.GotConn,
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), t))
	return w, req
}

func checksum(data []byte) (string, error) {
	sha := sha256.New()
	_, err := sha.Write(data)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(sha.Sum(nil)), nil
}

type connectionWatcher struct {
	gotConn bool
}

func (c *connectionWatcher) GotConn(_ httptrace.GotConnInfo) {
	c.gotConn = true
}

func EncodeAndValidateInput(user *models.User, hookConfig models.HookConfig, metadata map[string]interface{}) (interface{}, error) {
	var request interface{}
	var err error
	switch hookConfig.ExtensibilityPoint {
	case CustomSMSExtensibilityPoint:
		request, err = TransformCustomSMSExtensibilityPointInputs(user, metadata)
	default:
		return nil, internalServerError("failed to encode webhook").WithInternalError(err)
	}
	if err != nil {
		return nil, internalServerError("failed to encode webhook").WithInternalError(err)
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	if err := validateSchema(hookConfig.RequestSchema, string(jsonData)); err != nil {
		return nil, err
	}

	return jsonData, nil
}

func DecodeAndValidateResponse(hookConfig models.HookConfig, resp io.ReadCloser) (output interface{}, err error) {
	var jsonData []byte
	var decodedResponse interface{}
	switch hookConfig.ExtensibilityPoint {
	// Repeat for all possible Hook types
	case CustomSMSExtensibilityPoint:
		var outputs *CustomSMSHookResponse
		decoder := json.NewDecoder(resp)
		if err = decoder.Decode(outputs); err != nil {
			return nil, webhookResponseError(err.Error()).WithInternalError(err)
		}
		decodedResponse = outputs

	default:
		return nil, webhookResponseError(err.Error()).WithInternalError(err)
	}

	if validationErr := validateSchema(hookConfig.ResponseSchema, string(jsonData)); validationErr != nil {
		return nil, validationErr
	}

	jsonData, err = json.Marshal(decodedResponse)
	if err != nil {
		return nil, webhookResponseError(err.Error()).WithInternalError(err)
	}
	return jsonData, nil
}

func validateSchema(schema map[string]interface{}, jsonDataAsString string) error {
	jsonLoader := gojsonschema.NewStringLoader(jsonDataAsString)
	requestJSON, err := json.Marshal(schema)
	if err != nil {
		return err
	}

	schemaLoader := gojsonschema.NewStringLoader(string(requestJSON))
	validationResult, err := gojsonschema.Validate(schemaLoader, jsonLoader)
	if err != nil {
		fmt.Printf("Error loading JSON data: %s\n", err.Error())
		return err
	}
	if validationResult.Valid() {
		return nil
	} else {
		for _, desc := range validationResult.Errors() {
			fmt.Printf("- %s\n", desc)
		}
		return errors.New("JSON data is not valid against the schema.")
	}
}
