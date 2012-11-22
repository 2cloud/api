package main

import (
	"encoding/json"
	"errors"
	"get.2cloud.org/twocloud"
	"io/ioutil"
	"net/http"
	"net/url"
	"secondbit.org/ruid"
	"time"
)

type tokenRequest struct {
	Access  string    `json:"access"`
	Refresh string    `json:"refresh,omitempty"`
	Expires time.Time `json:"expires,omitempty"`
}

type Credentials [2]string

func parseCallback(callback string) (*url.URL, error) {
	if callback == "" {
		return nil, errors.New("Callback must be specified.")
	}
	_, err := url.QueryUnescape(callback)
	if err != nil {
		return nil, errors.New("Bad callback formatting.")
	}
	cbURL, err := url.Parse(callback)
	if err != nil {
		return nil, errors.New("Invalid callback URL")
	}
	return cbURL, nil
}

func oauthRedirect(w http.ResponseWriter, r *twocloud.RequestBundle) {
	callback := r.Request.URL.Query().Get("callback")
	_, err := parseCallback(callback)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, err.Error(), []interface{}{})
		return
	}
	url := r.GetOAuthAuthURL(r.Config.OAuth.ClientID, r.Config.OAuth.ClientSecret, r.Config.OAuth.CallbackURL, callback)
	http.Redirect(w, r.Request, url, http.StatusFound)
	return
}

func oauthCallback(w http.ResponseWriter, r *twocloud.RequestBundle) {
	code := r.Request.URL.Query().Get("code")
	if code == "" {
		Respond(w, r, http.StatusBadRequest, "No auth code specified.", []interface{}{})
		return
	}
	state := r.Request.URL.Query().Get("state")
	callback, err := parseCallback(state)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, err.Error(), []interface{}{})
		return
	}
	access, refresh, exp, err := r.GetOAuthAccessToken(code)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	account, err := r.GetAccount(access, refresh, exp)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	values := callback.Query()
	if account.UserID != ruid.RUID(0) {
		user, err := r.GetUser(account.UserID)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Error while logging you in. We're looking into it.", []interface{}{})
			return
		}
		values.Set("user", user.Username)
		values.Set("secret", user.Secret)
	} else {
		values.Set("id", account.ID.String())
		values.Set("email", account.Email)
		values.Set("givenName", account.GivenName)
		values.Set("familyName", account.FamilyName)
	}
	callback.RawQuery = values.Encode()
	http.Redirect(w, r.Request, callback.String(), http.StatusFound)
	return
}

func oauthToken(w http.ResponseWriter, r *twocloud.RequestBundle) {
	var tokens tokenRequest
	body, err := ioutil.ReadAll(r.Request.Body)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	err = json.Unmarshal(body, &tokens)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusBadRequest, "Error decoding request.", []interface{}{})
		return
	}
	if tokens.Access == "" {
		Respond(w, r, http.StatusBadRequest, "access token must be supplied.", []interface{}{})
		return
	}
	account, err := r.GetAccount(tokens.Access, tokens.Refresh, tokens.Expires)
	if err != nil {
		r.Log.Error(err.Error())
		if err == twocloud.OAuthAuthError {
			Respond(w, r, http.StatusUnauthorized, err.Error(), []interface{}{})
			return
		} else if oauthError, ok := err.(twocloud.OAuthError); ok {
			Respond(w, r, http.StatusUnauthorized, oauthError.Error(), []interface{}{})
			return
		}
		Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	if account.UserID != ruid.RUID(0) {
		user, err := r.GetUser(account.UserID)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Error while logging you in. We're looking into it.", []interface{}{})
			return
		}
		setLastModified(w, user.LastActive)
		Respond(w, r, http.StatusOK, "Successfully authenticated the user", []interface{}{user})
		return
	}
	Respond(w, r, http.StatusCreated, "Successfully created a new account", []interface{}{account})
	setLastModified(w, account.Added)
	return
}

func updateAccountTokens(w http.ResponseWriter, r *twocloud.RequestBundle) {
	var tokens tokenRequest
	accountID := r.Request.URL.Query().Get(":account")
	if accountID == "" {
		Respond(w, r, http.StatusBadRequest, "Must specify an account ID.", []interface{}{})
		return
	}
	id, err := ruid.RUIDFromString(accountID)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, "Invalid account ID.", []interface{}{})
		return
	}
	account, err := r.GetAccountByID(id)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	if account.UserID != r.AuthUser.ID {
		Respond(w, r, http.StatusForbidden, "You don't have access to that account.", []interface{}{})
		return
	}
	body, err := ioutil.ReadAll(r.Request.Body)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	err = json.Unmarshal(body, &tokens)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusBadRequest, "Error decoding request.", []interface{}{})
		return
	}
	if tokens.Access == "" {
		Respond(w, r, http.StatusBadRequest, "access token must be supplied.", []interface{}{})
		return
	}
	err = r.UpdateAccountTokens(account, tokens.Access, tokens.Refresh, tokens.Expires)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, r, http.StatusOK, "Successfully updated the account tokens", []interface{}{account})
	return
}

func removeAccount(w http.ResponseWriter, r *twocloud.RequestBundle) {
}

func refreshAccount(w http.ResponseWriter, r *twocloud.RequestBundle) {
	accountID := r.Request.URL.Query().Get(":account")
	if accountID == "" {
		Respond(w, r, http.StatusBadRequest, "Must specify an account ID.", []interface{}{})
		return
	}
	id, err := ruid.RUIDFromString(accountID)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, "Invalid account ID.", []interface{}{})
		return
	}
	account, err := r.GetAccountByID(id)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	if account.UserID != r.AuthUser.ID {
		Respond(w, r, http.StatusForbidden, "You don't have access to that account.", []interface{}{})
		return
	}
	account, err = r.UpdateAccountData(account)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, r, http.StatusOK, "Successfully updated the account", []interface{}{account})
	return
}

func generateTmpCredentials(w http.ResponseWriter, r *twocloud.RequestBundle) {
	strs, err := r.CreateTempCredentials(r.AuthUser)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	creds := Credentials(strs)
	Respond(w, r, http.StatusCreated, "Generated temporary credentials", []interface{}{creds})
	return
}

func authTmpCredentials(w http.ResponseWriter, r *twocloud.RequestBundle) {
	cred1 := r.Request.URL.Query().Get("cred1")
	cred2 := r.Request.URL.Query().Get("cred2")
	if cred1 == "" || cred2 == "" {
		Respond(w, r, http.StatusBadRequest, "Both temporary credentials must be supplied", []interface{}{})
		return
	}
	id, err := r.CheckTempCredentials(cred1, cred2)
	if err == twocloud.InvalidCredentialsError {
		Respond(w, r, http.StatusUnauthorized, "Invalid credentials", []interface{}{})
		return
	} else if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	user, err := r.GetUser(id)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, r, http.StatusOK, "Successfully authenticated the user", []interface{}{user})
	return
}

func auditAccount(w http.ResponseWriter, r *twocloud.RequestBundle) {
}
