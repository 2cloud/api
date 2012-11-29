package main

import (
	"encoding/json"
	"get.2cloud.org/twocloud"
	"io/ioutil"
	"net/http"
	"secondbit.org/ruid"
	"strconv"
	"strings"
)

func getGraceSubscriptions(w http.ResponseWriter, r *twocloud.RequestBundle) {
	if !r.AuthUser.IsAdmin {
		Respond(w, r, http.StatusForbidden, "You don't have permission to list expired subscriptions.", []interface{}{})
		return
	}
	var after, before ruid.RUID
	var err error
	afterstr := r.Request.URL.Query().Get("after")
	if afterstr != "" {
		after, err = ruid.RUIDFromString(afterstr)
		if err != nil {
			Respond(w, r, http.StatusBadRequest, "Invalid after ID.", []interface{}{})
			return
		}
	}
	beforestr := r.Request.URL.Query().Get("before")
	if beforestr != "" {
		before, err = ruid.RUIDFromString(beforestr)
		if err != nil {
			Respond(w, r, http.StatusBadRequest, "Invalid before ID.", []interface{}{})
			return
		}
	}
	count := 20
	countstr := r.Request.URL.Query().Get("count")
	if countstr != "" {
		newcount, err := strconv.Atoi(countstr)
		if err != nil {
			Respond(w, r, http.StatusBadRequest, "Invalid count.", []interface{}{})
			return
		}
		if newcount > 0 && newcount <= 100 {
			count = newcount
		}
	}
	users, err := r.GetGraceSubscriptions(after, before, count)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, r, http.StatusOK, "Susccessfully retrieved a list of users", []interface{}{users})
	return
}

func getUserSubscription(w http.ResponseWriter, r *twocloud.RequestBundle) {
	username := r.Request.URL.Query().Get(":username")
	user := r.AuthUser
	if strings.ToLower(username) != strings.ToLower(r.AuthUser.Username) {
		if !r.AuthUser.IsAdmin {
			Respond(w, r, http.StatusUnauthorized, "You don't have access to that user's subscription.", []interface{}{})
			return
		}
		id, err := r.GetUserID(username)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
		user, err = r.GetUser(id)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
	}
	Respond(w, r, http.StatusOK, "Successfully retrieved subscription information", []interface{}{user.Subscription})
	return
}

func startSubscription(w http.ResponseWriter, r *twocloud.RequestBundle) {
	username := r.Request.URL.Query().Get(":username")
	user := r.AuthUser
	if strings.ToLower(username) != strings.ToLower(r.AuthUser.Username) {
		if !r.AuthUser.IsAdmin {
			Respond(w, r, http.StatusUnauthorized, "You don't have access to that user's subscription.", []interface{}{})
			return
		}
		id, err := r.GetUserID(username)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
		user, err = r.GetUser(id)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
	}
	var req twocloud.Subscription
	body, err := ioutil.ReadAll(r.Request.Body)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	err = json.Unmarshal(body, &req)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusBadRequest, "Error decoding request.", []interface{}{})
		return
	}
	err = r.CreateSubscription(user, req.AuthTokens)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, r, http.StatusOK, "Successfully created the subscription", []interface{}{user.Subscription})
	return
}

func updateSubscription(w http.ResponseWriter, r *twocloud.RequestBundle) {
	username := r.Request.URL.Query().Get(":username")
	user := r.AuthUser
	if strings.ToLower(username) != strings.ToLower(r.AuthUser.Username) {
		if !r.AuthUser.IsAdmin {
			Respond(w, r, http.StatusUnauthorized, "You don't have access to that user's subscription.", []interface{}{})
			return
		}
		id, err := r.GetUserID(username)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
		user, err = r.GetUser(id)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
	}
	var req twocloud.Subscription
	body, err := ioutil.ReadAll(r.Request.Body)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	err = json.Unmarshal(body, &req)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusBadRequest, "Error decoding request.", []interface{}{})
		return
	}
	if len(req.AuthTokens) > 0 {
		err = r.UpdateSubscriptionPaymentSource(user, req.AuthTokens)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
	}
	if r.AuthUser.IsAdmin {
		err = r.UpdateSubscription(user, req.Expires)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
			return
		}
		user, err = r.GetUser(user.ID)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
	}
	Respond(w, r, http.StatusOK, "Successfully updated the subscription", []interface{}{user.Subscription})
	return
}

func cancelSubscription(w http.ResponseWriter, r *twocloud.RequestBundle) {
	username := r.Request.URL.Query().Get(":username")
	user := r.AuthUser
	if strings.ToLower(username) != strings.ToLower(r.AuthUser.Username) {
		if !r.AuthUser.IsAdmin {
			Respond(w, r, http.StatusUnauthorized, "You don't have access to that user's subscription.", []interface{}{})
			return
		}
		id, err := r.GetUserID(username)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
		user, err = r.GetUser(id)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
	}
	sub := *user.Subscription
	err := r.CancelSubscription(user)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, r, http.StatusOK, "Successfully canceled the subscription", []interface{}{sub})
	return

}

func auditSubscription(w http.ResponseWriter, r *twocloud.RequestBundle) {
}
