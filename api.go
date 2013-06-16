package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"get.2cloud.org/twocloud"
	"github.com/bmizerany/pat"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var config twocloud.Config
var VERSION = "1.0.0"

func AuthenticateRequest(w http.ResponseWriter, r *http.Request, deviceRequired bool, bundle *RequestBundle) bool {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		Respond(w, http.StatusUnauthorized, "No credentials supplied.", []interface{}{MissingParam("headers.authorization")})
		return false
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] != "Basic" {
		Respond(w, http.StatusUnauthorized, "Invalid credentials.", []interface{}{InvalidFormat("headers.authorization")})
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		bundle.Persister.Log.Error(err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		Respond(w, http.StatusUnauthorized, "Error while decoding credentials.", []interface{}{InvalidFormat("headers.authorization")})
		return false
	}
	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		Respond(w, http.StatusUnauthorized, "No credentials supplied.", []interface{}{InvalidFormat("headers.authorization")})
		return false
	}
	user := credentials[0]
	secret := credentials[1]
	authUser, err := bundle.Persister.Authenticate(user, secret)
	if err == twocloud.InvalidCredentialsError || err == twocloud.UserNotFoundError {
		if err == twocloud.InvalidCredentialsError {
			bundle.Persister.Log.Warn("Invalid auth attempt on %s's account.", user)
			Respond(w, http.StatusUnauthorized, "Invalid credentials.", []interface{}{InvalidValue("headers.authorization")})
		}
		Respond(w, http.StatusUnauthorized, "Invalid credentials.", []interface{}{NotFound("headers.authorization.username")})
		return false
	} else if err != nil {
		bundle.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return false
	}
	bundle.AuthUser = &authUser
	if deviceRequired {
		if r.Header.Get("From") == "" {
			Respond(w, http.StatusBadRequest, "From header not set.", []interface{}{MissingParam("headers.from")})
			return false
		}
		deviceId, err := strconv.ParseUint(r.Header.Get("From"), 10, 64)
		if err != nil {
			bundle.Persister.Log.Debug(err.Error())
			Respond(w, http.StatusBadRequest, "From header must be an integer.", []interface{}{InvalidFormat("headers.from")})
			return false
		}
		device, err := bundle.Persister.GetDevice(twocloud.ID(deviceId))
		if err != nil {
			if err == twocloud.DeviceNotFoundError {
				Respond(w, http.StatusBadRequest, "From header not a valid device ID.", []interface{}{NotFound("headers.from")})
				return false
			}
			bundle.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
			return false
		}
		if device.UserID != bundle.AuthUser.ID && !bundle.AuthUser.IsAdmin {
			Respond(w, http.StatusBadRequest, "From header set to a device you do not own.", []interface{}{AccessDenied("headers.from")})
			return false
		}
		device, err = bundle.Persister.UpdateDeviceLastSeen(device, r.RemoteAddr)
		if err != nil {
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
			return false
		}
		bundle.AuthDevice = &device
	}
	return true
}

type RequestHandler func(http.ResponseWriter, *http.Request, *RequestBundle)

type Request struct {
	Handler        RequestHandler
	AuthRequired   bool
	DeviceRequired bool
}

type RequestBundle struct {
	Persister  *twocloud.Persister
	AuthUser   *twocloud.User
	AuthDevice *twocloud.Device
}

func newBundle(p *twocloud.Persister) *RequestBundle {
	return &RequestBundle{
		Persister:  p,
		AuthUser:   nil,
		AuthDevice: nil,
	}
}

var UnauthorisedAccessAttempt = errors.New("Unauthorised access attempt.")

func (b *RequestBundle) getUser(username string) (twocloud.User, error) {
	user := *b.AuthUser
	var err error
	if strings.ToLower(username) != strings.ToLower(user.Username) {
		if !b.AuthUser.IsAdmin {
			err = UnauthorisedAccessAttempt
			return user, err
		}
		user, err = b.Persister.GetUserByUsername(username)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			return user, err
		}
	}
	return user, err
}

func (b *RequestBundle) getDevice(id twocloud.ID) (twocloud.Device, error) {
	device := *b.AuthDevice
	var err error
	if device.ID != id {
		device, err = b.Persister.GetDevice(id)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			return device, err
		}
		if device.UserID != b.AuthUser.ID && !b.AuthUser.IsAdmin {
			err = UnauthorisedAccessAttempt
			return device, err
		}
	}
	return device, err
}

func (rb *Request) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if config.MaintenanceMode {
		w.Header().Set("Retry-After", "300")
		Respond(w, http.StatusServiceUnavailable, "Undergoing maintenance. Please try again after 5 minutes.", []interface{}{})
		return
	}
	p, err := twocloud.NewPersister(config)
	defer p.Close()
	if err != nil {
		os.Stdout.WriteString("Error creating Persister: " + err.Error() + "\n")
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	bundle := newBundle(p)
	if !rb.AuthRequired || AuthenticateRequest(w, r, rb.DeviceRequired, bundle) {
		rb.Handler(w, r, bundle)
	}
}

func newRequest(f RequestHandler, authRequired bool) *Request {
	return &Request{
		Handler:        f,
		AuthRequired:   authRequired,
		DeviceRequired: true,
	}
}

func devicelessRequest(f RequestHandler, authRequired bool) *Request {
	return &Request{
		Handler:        f,
		AuthRequired:   authRequired,
		DeviceRequired: false,
	}
}

func main() {
	router := pat.New()

	var port, configFile string
	flag.StringVar(&port, "p", "80", "The port to listen on")
	flag.StringVar(&configFile, "cfg", "config.json", "The config file to use")
	flag.Parse()

	cfgBytes, err := ioutil.ReadFile(configFile)
	if err != nil {
		panic(err.Error())
	}
	err = json.Unmarshal(cfgBytes, &config)
	if err != nil {
		panic(err.Error())
	}

	// Accounts
	router.Get("/accounts/redirect", devicelessRequest(oauthRedirect, false))
	router.Get("/accounts/oauth", devicelessRequest(oauthCallback, false))
	router.Post("/accounts/auth", devicelessRequest(oauthToken, false))
	router.Get("/accounts/tmp", newRequest(authTmpCredentials, false))
	router.Post("/accounts/tmp", newRequest(generateTmpCredentials, true))

	router.Put("/accounts/:account", newRequest(updateAccountTokens, true))
	router.Del("/accounts/:account", newRequest(removeAccount, true))
	router.Post("/accounts/:account", newRequest(refreshAccount, true))

	// Users
	router.Get("/users", newRequest(getUsers, true))
	router.Post("/users", devicelessRequest(createUser, false))
	router.Get("/users/:username", newRequest(getUser, true))
	router.Put("/users/:username", newRequest(updateUser, true))
	router.Del("/users/:username", newRequest(deleteUser, true))
	router.Get("/users/:username/accounts", newRequest(getUserAccounts, true))
	router.Post("/users/:username/secret", newRequest(resetSecret, true))
	router.Put("/users/:username/verify", devicelessRequest(verifyEmail, true))

	// Devices
	router.Get("/users/:username/devices", devicelessRequest(getDevices, true))
	router.Post("/users/:username/devices", devicelessRequest(newDevice, true))
	router.Get("/users/:username/devices/:device", newRequest(getDevice, true))
	router.Put("/users/:username/devices/:device", newRequest(updateDevice, true))
	router.Del("/users/:username/devices/:device", newRequest(deleteDevice, true))

	// Links
	router.Get("/users/:username/links", newRequest(getLinks, true))
	router.Get("/users/:username/devices/:device/links", newRequest(getLinks, true))
	router.Post("/users/:username/devices/:device/links", newRequest(sendLinks, true))
	router.Get("/users/:username/devices/:device/links/:link", newRequest(getLink, true))
	router.Put("/users/:username/devices/:device/links/:link", newRequest(updateLink, true))
	router.Del("/users/:username/devices/:device/links/:link", newRequest(deleteLink, true))

	// Notifications
	router.Get("/users/:username/devices/:device/notifications", newRequest(getNotifications, true))
	router.Get("/users/:username/notifications", newRequest(getNotifications, true))
	router.Get("/users/:username/notifications/:notification", newRequest(getNotification, true))

	router.Post("/users/:username/devices/:device/notifications", newRequest(sendNotification, true))
	router.Post("/users/:username/notifications", newRequest(sendNotification, true))
	router.Post("/notifications", newRequest(sendNotification, true))

	router.Put("/users/:username/notifications/:notification", newRequest(markNotificationRead, true))
	router.Del("/users/:username/notifications/:notification", newRequest(deleteNotification, true))

	// Subscriptions
	router.Get("/subscriptions/in_grace_period", newRequest(getGraceSubscriptions, true))
	router.Get("/users/:username/subscription", newRequest(getUserSubscription, true))

	router.Post("/users/:username/subscription", devicelessRequest(startSubscription, true))
	router.Put("/users/:username/subscription", newRequest(updateSubscription, true))
	router.Del("/users/:username/subscription", newRequest(cancelSubscription, true))

	// Funding Sources
	router.Get("/users/:username/funding_sources", newRequest(getFundingSources, true))
	router.Get("/users/:username/funding_sources/:provider/:id", newRequest(getFundingSource, true))
	router.Post("/users/:username/funding_sources", newRequest(addFundingSource, true))
	router.Put("/users/:username/funding_sources/:provider/:id", newRequest(updateFundingSource, true))
	router.Del("/users/:username/funding_sources/:provider/:id", newRequest(deleteFundingSource, true))

	// Campaigns
	router.Get("/campaigns", devicelessRequest(getCampaigns, false))
	router.Get("/campaigns/:id", devicelessRequest(getCampaign, false))
	router.Post("/campaigns", newRequest(newCampaign, true))
	router.Put("/campaigns/:id", newRequest(updateCampaign, true))
	router.Del("/campaigns/:id", newRequest(deleteCampaign, true))

	os.Stdout.WriteString("Listening on port " + port + "\n")
	err = http.ListenAndServe(":"+port, router)
	if err != nil {
		panic(err.Error())
	}
}

func setLastModified(w http.ResponseWriter, t time.Time) {
	w.Header().Set("Last-Modified", t.UTC().Format(http.TimeFormat))
}
