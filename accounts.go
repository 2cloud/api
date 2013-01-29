package main

import (
	"errors"
	"get.2cloud.org/twocloud"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type account struct {
	ID twocloud.ID `json:"id"`
}

type tokens struct {
	Access  *string   `json:"access"`
	Refresh *string   `json:"refresh,omitempty"`
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

func oauthRedirect(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	callback := r.URL.Query().Get("callback")
	_, err := parseCallback(callback)
	if err != nil {
		Respond(w, http.StatusBadRequest, err.Error(), []interface{}{})
		return
	}
	url := twocloud.GetGoogleAuthURL(b.Persister.Config.OAuth, callback)
	http.Redirect(w, r, url, http.StatusFound)
	return
}

func oauthCallback(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	code := r.URL.Query().Get("code")
	if code == "" {
		Respond(w, http.StatusBadRequest, "No auth code specified.", []interface{}{})
		return
	}
	state := r.URL.Query().Get("state")
	callback, err := parseCallback(state)
	if err != nil {
		Respond(w, http.StatusBadRequest, err.Error(), []interface{}{})
		return
	}
	access, refresh, exp, err := twocloud.GetGoogleAccessToken(b.Persister.Config.OAuth, code)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	account, err := b.Persister.GetAccountByTokens(access, refresh, exp)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	values := callback.Query()
	if account.UserID != 0 {
		user, err := b.Persister.GetUser(account.UserID)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Error while logging you in. We're looking into it.", []interface{}{})
			return
		}
		values.Set("user", user.Username)
		values.Set("secret", user.Secret)
	} else {
		values.Set("id", strconv.FormatUint(uint64(account.ID), 10))
		values.Set("email", account.Email)
		values.Set("givenName", account.GivenName)
		values.Set("familyName", account.FamilyName)
	}
	callback.RawQuery = values.Encode()
	http.Redirect(w, r, callback.String(), http.StatusFound)
	return
}

func oauthToken(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	request, err := getRequest(r)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		if isUnmarshalError(err) {
			Respond(w, http.StatusBadRequest, "Error decoding request.", []interface{}{})
		} else {
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		}
		return
	}
	if request.Tokens.Access == nil {
		Respond(w, http.StatusBadRequest, "Access token must be supplied.", []interface{}{})
		return
	}
	account, err := b.Persister.GetAccountByTokens(request.Tokens.Access, request.Tokens.Refresh, request.Tokens.Expires)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		if err == twocloud.OAuthAuthError {
			Respond(w, http.StatusUnauthorized, err.Error(), []interface{}{})
			return
		} else if oauthError, ok := err.(twocloud.OAuthError); ok {
			Respond(w, http.StatusUnauthorized, oauthError.Error(), []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	if account.UserID != 0 {
		user, err := b.Persister.GetUser(account.UserID)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Error while logging you in. We're looking into it.", []interface{}{})
			return
		}
		setLastModified(w, user.LastActive)
		Respond(w, http.StatusOK, "Successfully authenticated the user", []interface{}{user})
		return
	}
	Respond(w, http.StatusCreated, "Successfully created a new account", []interface{}{account})
	setLastModified(w, account.Added)
	return
}

func updateAccountTokens(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	accountID := r.URL.Query().Get(":account")
	if accountID == "" {
		Respond(w, http.StatusBadRequest, "Must specify an account ID.", []interface{}{})
		return
	}
	id, err := strconv.ParseUint(accountID, 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid account ID.", []interface{}{})
		return
	}
	request, err := getRequest(r)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		if isUnmarshalError(err) {
			Respond(w, http.StatusBadRequest, "Error decoding request.", []interface{}{})
		} else {
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		}
		return
	}
	if request.Tokens.Access == nil {
		Respond(w, http.StatusBadRequest, "Access token must be supplied.", []interface{}{})
		return
	}
	account, err := b.Persister.GetAccountByID(twocloud.ID(id))
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	if account.UserID != b.AuthUser.ID && !b.AuthUser.IsAdmin {
		Respond(w, http.StatusForbidden, "You don't have access to that account.", []interface{}{})
		return
	}
	err = b.Persister.UpdateAccountTokens(account, request.Tokens.Access, request.Tokens.Refresh, request.Tokens.Expires)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, http.StatusOK, "Successfully updated the account tokens", []interface{}{account})
	return
}

func removeAccount(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	accountID := r.URL.Query().Get(":account")
	if accountID == "" {
		Respond(w, http.StatusBadRequest, "Must specify an account ID.", []interface{}{})
		return
	}
	id, err := strconv.ParseUint(accountID, 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid account ID.", []interface{}{})
		return
	}
	account, err := b.Persister.GetAccountByID(twocloud.ID(id))
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	if account.UserID != b.AuthUser.ID && !b.AuthUser.IsAdmin {
		Respond(w, http.StatusForbidden, "You don't have access to that account.", []interface{}{})
		return
	}
	err = b.Persister.DeleteAccount(account)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, http.StatusOK, "Successfully deleted the account", []interface{}{account})
	return
}

func refreshAccount(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	accountID := r.URL.Query().Get(":account")
	if accountID == "" {
		Respond(w, http.StatusBadRequest, "Must specify an account ID.", []interface{}{})
		return
	}
	id, err := strconv.ParseUint(accountID, 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid account ID.", []interface{}{})
		return
	}
	account, err := b.Persister.GetAccountByID(twocloud.ID(id))
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	if account.UserID != b.AuthUser.ID && !b.AuthUser.IsAdmin {
		Respond(w, http.StatusForbidden, "You don't have access to that account.", []interface{}{})
		return
	}
	account, err = b.Persister.UpdateAccountData(account)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, http.StatusOK, "Successfully updated the account", []interface{}{account})
	return
}

func generateTmpCredentials(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	strs, err := b.Persister.CreateTempCredentials(*b.AuthUser)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	creds := Credentials(strs)
	Respond(w, http.StatusCreated, "Generated temporary credentials", []interface{}{creds})
	return
}

func authTmpCredentials(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	cred1 := r.URL.Query().Get("cred1")
	cred2 := r.URL.Query().Get("cred2")
	if cred1 == "" || cred2 == "" {
		Respond(w, http.StatusBadRequest, "Both temporary credentials must be supplied", []interface{}{})
		return
	}
	id, err := b.Persister.CheckTempCredentials(cred1, cred2)
	if err == twocloud.InvalidCredentialsError {
		Respond(w, http.StatusUnauthorized, "Invalid credentials", []interface{}{})
		return
	} else if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	user, err := b.Persister.GetUser(id)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, http.StatusOK, "Successfully authenticated the user", []interface{}{user})
	return
}

func auditAccount(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
}
