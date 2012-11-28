package main

import (
	"get.2cloud.org/twocloud"
	"net/http"
	"secondbit.org/ruid"
	"strconv"
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
	subscriptions, err := r.GetGraceSubscriptions(after, before, count)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, r, http.StatusOK, "Susccessfully retrieved a list of subscriptions", []interface{}{subscriptions})
	return
}

func getUserSubscription(w http.ResponseWriter, r *twocloud.RequestBundle) {
}

func getSubscription(w http.ResponseWriter, r *twocloud.RequestBundle) {
}

func startSubscription(w http.ResponseWriter, r *twocloud.RequestBundle) {
}

func updateSubscription(w http.ResponseWriter, r *twocloud.RequestBundle) {
}

func cancelSubscription(w http.ResponseWriter, r *twocloud.RequestBundle) {
}

func auditSubscription(w http.ResponseWriter, r *twocloud.RequestBundle) {
}
