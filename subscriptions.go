package main

import (
	"get.2cloud.org/twocloud"
	"net/http"
	"strconv"
	"time"
)

type subscription struct {
	Expires time.Time `json:"expires,omitempty"`
}

func getGraceSubscriptions(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	if !b.AuthUser.IsAdmin {
		Respond(w, http.StatusForbidden, "You don't have permission to list expired subscriptions.", []interface{}{AccessDenied("")})
		return
	}
	var after, before time.Time
	var err error
	afterstr := r.URL.Query().Get("after")
	if afterstr != "" {
		after, err = time.Parse(time.RFC3339, afterstr)
		if err != nil {
			Respond(w, http.StatusBadRequest, "Invalid after timestamp. Needs to be URL-encoded RFC3339.", []interface{}{InvalidFormat("after")})
			return
		}
	}
	beforestr := r.URL.Query().Get("before")
	if beforestr != "" {
		before, err = time.Parse(time.RFC3339, beforestr)
		if err != nil {
			Respond(w, http.StatusBadRequest, "Invalid before timestamp. Needs to be URL-encoded RFC3339.", []interface{}{InvalidFormat("before")})
			return
		}
	}
	count := 20
	countstr := r.URL.Query().Get("count")
	if countstr != "" {
		newcount, err := strconv.Atoi(countstr)
		if err != nil {
			Respond(w, http.StatusBadRequest, "Invalid count.", []interface{}{InvalidFormat("count")})
			return
		}
		if newcount > 0 && newcount <= 100 {
			count = newcount
		} else if newcount <= 0 {
			Respond(w, http.StatusBadRequest, "Count must be greater than 0.", []interface{}{TooShort("count")})
			return
		} else if newcount > 100 {
			Respond(w, http.StatusBadRequest, "Count must be less than 100.", []interface{}{TooLong("count")})
			return
		}
	}
	users, err := b.Persister.GetSubscriptionsByExpiration(after, before, count)
	if err != nil {
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Susccessfully retrieved a list of users", []interface{}{users})
	return
}

func getUserSubscription(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Missing username.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's subscription.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully retrieved subscription information", []interface{}{user.Subscription})
	return
}

func startSubscription(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Missing username.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's subscription.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	err = b.Persister.StartRenewingSubscription(user.Subscription)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully set the subscription to auto-renew.", []interface{}{user.Subscription})
	return
}

func updateSubscription(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	if !b.AuthUser.IsAdmin {
		Respond(w, http.StatusUnauthorized, "You need administrative credentials to update a user's subscription.", []interface{}{AccessDenied("")})
		return
	}
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Missing username.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	request, err := getRequest(r)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		if isUnmarshalError(err) {
			Respond(w, http.StatusBadRequest, "Error decoding request.", []interface{}{BadRequestFormat("")})
		} else {
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		}
		return
	}
	if request.Subscription == nil {
		Respond(w, http.StatusBadRequest, "Subscription must be included in request.", []interface{}{MissingParam("subscription")})
		return
	}
	if request.Subscription.Expires.IsZero() {
		Respond(w, http.StatusBadRequest, "Subscription renewal date must be set.", []interface{}{MissingParam("subscription.renews")})
		return
	}
	err = b.Persister.UpdateSubscriptionExpiration(user.Subscription, request.Subscription.Expires)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully updated the subscription", []interface{}{user.Subscription})
	return
}

func cancelSubscription(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Missing username.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's subscription.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	err = b.Persister.CancelRenewingSubscription(user.Subscription)
	if err != nil {
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully canceled the subscription", []interface{}{user.Subscription})
	return

}
