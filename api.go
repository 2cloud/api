package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"get.2cloud.org/twocloud"
	"github.com/bmizerany/pat"
	"github.com/noeq/noeq"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var config twocloud.Config
var radix *twocloud.Radix
var gen *noeq.Client

func AuthenticateRequest(w http.ResponseWriter, deviceRequired bool, bundle *twocloud.RequestBundle) bool {
	auth := bundle.Request.Header.Get("Authorization")
	if auth == "" {
		Respond(w, bundle, http.StatusUnauthorized, "No credentials supplied.", []interface{}{})
		return false
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] != "Basic" {
		Respond(w, bundle, http.StatusUnauthorized, "Invalid credentials.", []interface{}{})
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		bundle.Log.Error(err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		Respond(w, bundle, http.StatusUnauthorized, "Error while decoding credentials.", []interface{}{})
		return false
	}
	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		Respond(w, bundle, http.StatusUnauthorized, "No credentials supplied.", []interface{}{})
		return false
	}
	user := credentials[0]
	secret := credentials[1]
	authUser, err := bundle.Authenticate(user, secret)
	if err == twocloud.InvalidCredentialsError || err == twocloud.UserNotFoundError {
		Respond(w, bundle, http.StatusUnauthorized, "Invalid credentials.", []interface{}{})
		return false
	} else if _, ok := err.(*twocloud.SubscriptionExpiredError); ok {
		Respond(w, bundle, http.StatusPaymentRequired, "Your subscription has expired.", []interface{}{})
		return false
	} else if _, ok := err.(*twocloud.SubscriptionExpiredWarning); ok {
		w.Header().Set("Warning", "299 2cloud \""+err.Error()+"\"")
	} else if err != nil {
		bundle.Log.Error(err.Error())
		Respond(w, bundle, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return false
	}
	bundle.AuthUser = authUser
	if deviceRequired {
		if bundle.Request.Header.Get("From") == "" {
			Respond(w, bundle, http.StatusBadRequest, "From header not set.", []interface{}{})
			return false
		}
		deviceId, err := strconv.ParseUint(bundle.Request.Header.Get("From"), 10, 64)
		if err != nil {
			bundle.Log.Error(err.Error())
			Respond(w, bundle, http.StatusInternalServerError, "Internal server error.", []interface{}{})
			return false
		}
		device, err := bundle.GetDevice(deviceId)
		if err != nil {
			bundle.Log.Error(err.Error())
			Respond(w, bundle, http.StatusInternalServerError, "Internal server error.", []interface{}{})
			return false
		}
		if device.UserID != bundle.AuthUser.ID && !bundle.AuthUser.IsAdmin {
			Respond(w, bundle, http.StatusBadRequest, "From header set to a device you do not own.", []interface{}{})
			return false
		}
		device, err = bundle.UpdateDeviceLastSeen(device, bundle.Request.RemoteAddr)
		if err != nil {
			Respond(w, bundle, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return false
		}
		bundle.Device = device
	}
	return true
}

type RequestHandler func(http.ResponseWriter, *twocloud.RequestBundle)

type RequestBundle struct {
	Handler        RequestHandler
	AuthRequired   bool
	DeviceRequired bool
}

func (rb *RequestBundle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	bundle := &twocloud.RequestBundle{
		Config:    config,
		Repo:      radix,
		Request:   r,
		Log:       twocloud.StdOutLogger(twocloud.LogLevelDebug),
		Generator: gen,
	}
	if config.MaintenanceMode {
		w.Header().Set("Retry-After", "300")
		Respond(w, bundle, http.StatusServiceUnavailable, "Undergoing maintenance. Please try again after 5 minutes.", []interface{}{})
		return
	}
	if !rb.AuthRequired || AuthenticateRequest(w, rb.DeviceRequired, bundle) {
		rb.Handler(w, bundle)
	}
}

func newBundle(f RequestHandler, authRequired bool) *RequestBundle {
	return &RequestBundle{
		Handler:        f,
		AuthRequired:   authRequired,
		DeviceRequired: true,
	}
}

func devicelessBundle(f RequestHandler, authRequired bool) *RequestBundle {
	return &RequestBundle{
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
	radix = twocloud.NewRadix(config.Database)
	defer radix.Close()

	gen, err = noeq.New(config.Generator.Token, config.Generator.Address)
	if err != nil {
		panic(err.Error())
	}

	// Accounts
	router.Get("/accounts/redirect", devicelessBundle(oauthRedirect, false))
	router.Get("/accounts/oauth", devicelessBundle(oauthCallback, false))
	router.Post("/accounts/auth", devicelessBundle(oauthToken, false))
	router.Get("/accounts/tmp", newBundle(authTmpCredentials, false))
	router.Post("/accounts/tmp", newBundle(generateTmpCredentials, true))

	router.Put("/accounts/:account", newBundle(updateAccountTokens, true))
	router.Del("/accounts/:account", newBundle(removeAccount, true))
	router.Post("/accounts/:account", newBundle(refreshAccount, true))

	router.Get("/accounts/:account/audit", newBundle(auditAccount, true))

	// Users
	router.Get("/users", newBundle(getUsers, true))
	router.Post("/users", devicelessBundle(createUser, false))
	router.Get("/users/:username", newBundle(getUser, true))
	router.Put("/users/:username", newBundle(updateUser, true))
	router.Del("/users/:username", newBundle(deleteUser, true))
	router.Get("/users/:username/accounts", newBundle(getUserAccounts, true))
	router.Post("/users/:username/secret", newBundle(resetSecret, true))
	router.Put("/users/:username/verify", devicelessBundle(verifyEmail, true))

	router.Get("/users/:username/audit", newBundle(auditUser, true))

	// Devices
	router.Get("/users/:username/devices", newBundle(getDevices, true))
	router.Post("/users/:username/devices", devicelessBundle(newDevice, true))
	router.Get("/users/:username/devices/:device", newBundle(getDevice, true))
	router.Put("/users/:username/devices/:device", newBundle(updateDevice, true))
	router.Del("/users/:username/devices/:device", newBundle(deleteDevice, true))

	router.Get("/users/:username/devices/:device/audit", newBundle(auditDevice, true))

	// Links
	router.Get("/users/:username/links", newBundle(getLinks, true))
	router.Get("/users/:username/devices/:device/links", newBundle(getLinks, true))
	router.Post("/users/:username/devices/:device/links", newBundle(sendLinks, true))
	router.Get("/users/:username/devices/:device/links/:link", newBundle(getLink, true))
	router.Put("/users/:username/devices/:device/links/:link", newBundle(updateLink, true))
	router.Del("/users/:username/devices/:device/links/:link", newBundle(deleteLink, true))

	router.Get("/users/:username/devices/:device/links/:link/audit", newBundle(auditLink, true))

	// Notifications
	router.Get("/users/:username/devices/:device/notifications", newBundle(getNotifications, true))
	router.Get("/users/:username/notifications", newBundle(getNotifications, true))
	router.Get("/users/:username/notifications/:notification", newBundle(getNotification, true))

	router.Post("/users/:username/devices/:device/notifications", newBundle(sendNotification, true))
	router.Post("/users/:username/notifications", newBundle(sendNotification, true))
	router.Post("/notifications", newBundle(sendNotification, true))

	router.Put("/users/:username/notifications/:notification", newBundle(markNotificationRead, true))
	router.Del("/users/:username/notifications/:notification", newBundle(deleteNotification, true))

	router.Get("/users/:username/notifications/:notification/audit", newBundle(auditNotification, true))

	// Subscriptions
	router.Get("/subscriptions/in_grace_period", newBundle(getGraceSubscriptions, true))
	router.Get("/users/:username/subscription", newBundle(getUserSubscription, true))

	router.Post("/users/:username/subscription", devicelessBundle(startSubscription, true))
	router.Put("/users/:username/subscription", newBundle(updateSubscription, true))
	router.Del("/users/:username/subscription", newBundle(cancelSubscription, true))

	router.Get("/users/:username/subscription/audit", newBundle(auditSubscription, true))

	os.Stdout.WriteString("Listening on port " + port + "\n")
	err = http.ListenAndServe(":"+port, router)
	if err != nil {
		panic(err.Error())
	}
}

func setLastModified(w http.ResponseWriter, t time.Time) {
	w.Header().Set("Last-Modified", t.UTC().Format(http.TimeFormat))
}
