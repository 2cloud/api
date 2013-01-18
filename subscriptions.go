package main

import (
	"encoding/json"
	"get.2cloud.org/twocloud"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

func getGraceSubscriptions(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	if !b.AuthUser.IsAdmin {
		Respond(w, http.StatusForbidden, "You don't have permission to list expired subscriptions.", []interface{}{})
		return
	}
	var after, before time.Time
	var err error
	afterstr := r.URL.Query().Get("after")
	if afterstr != "" {
		after, err = time.Parse(time.RFC3339, afterstr)
		if err != nil {
			Respond(w, http.StatusBadRequest, "Invalid after timestamp. Needs to be URL-encoded RFC3339.", []interface{}{})
			return
		}
	}
	beforestr := r.URL.Query().Get("before")
	if beforestr != "" {
		before, err = time.Parse(time.RFC3339, beforestr)
		if err != nil {
			Respond(w, http.StatusBadRequest, "Invalid before timestamp. Needs to be URL-encoded RFC3339.", []interface{}{})
			return
		}
	}
	count := 20
	countstr := r.URL.Query().Get("count")
	if countstr != "" {
		newcount, err := strconv.Atoi(countstr)
		if err != nil {
			Respond(w, http.StatusBadRequest, "Invalid count.", []interface{}{})
			return
		}
		if newcount > 0 && newcount <= 100 {
			count = newcount
		}
	}
	users, err := b.Persister.GetSubscriptionsByExpiration(after, before, count)
	if err != nil {
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, http.StatusOK, "Susccessfully retrieved a list of users", []interface{}{users})
	return
}

func getUserSubscription(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's subscription.", []interface{}{})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, http.StatusOK, "Successfully retrieved subscription information", []interface{}{user.Subscription})
	return
}

func createSubscription(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's subscription.", []interface{}{})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	var req twocloud.Subscription
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	err = json.Unmarshal(body, &req)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusBadRequest, "Error decoding request.", []interface{}{})
		return
	}
	subscription, err := b.Persister.CreateSubscription(user.ID, req.FundingID, req.FundingSource, req.AutoRenew)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	user.Subscription = subscription
	Respond(w, http.StatusOK, "Successfully created the subscription", []interface{}{user.Subscription})
	return
}

func updateSubscription(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's subscription.", []interface{}{})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	var req twocloud.Subscription
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	err = json.Unmarshal(body, &req)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusBadRequest, "Error decoding request.", []interface{}{})
		return
	}
	if req.FundingID != 0 && req.FundingSource != "" {
		err = b.Persister.UpdateSubscriptionPaymentSource(user.Subscription, req.FundingID, req.FundingSource)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
	}
	if b.AuthUser.IsAdmin {
		err = b.Persister.UpdateSubscriptionExpiration(user.Subscription, req.Expires)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
			return
		}
	}
	Respond(w, http.StatusOK, "Successfully updated the subscription", []interface{}{user.Subscription})
	return
}

func cancelSubscription(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's subscription.", []interface{}{})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	sub := *user.Subscription
	err = b.Persister.CancelRenewingSubscription(user.Subscription)
	if err != nil {
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, http.StatusOK, "Successfully canceled the subscription", []interface{}{sub})
	return

}

func auditSubscription(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
}
