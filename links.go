package main

import (
	"get.2cloud.org/twocloud"
	"net/http"
	"secondbit.org/ruid"
	"strconv"
)

func getLinks(w http.ResponseWriter, r *twocloud.RequestBundle) {
	username := r.Request.URL.Query().Get(":username")
	user := r.AuthUser
	role := r.Request.URL.Query().Get("role")
	roleFlag := twocloud.RoleEither
	if role == "sender" {
		roleFlag = twocloud.RoleSender
	} else if role == "receiver" {
		roleFlag = twocloud.RoleReceiver
	}
	var after, before ruid.RUID
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
		before, err = ruid.RUIDFromSTring(beforestr)
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
	var links []twocloud.Link
	if strings.ToLower(username) != strings.ToLower(r.AuthUser.Username) {
		if !r.AuthUser.IsAdmin {
			Respond(w, r, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{})
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
	deviceID := r.Request.URL.Query().Get(":device")
	if deviceID != "" {
		id, err := ruid.RUIDFromString(r.Request.URL.Query().Get(":device"))
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
		device, err := r.GetDevice(id)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
		if device.UserID != user.ID {
			Respond(w, r, http.StatusBadRequest, "That device ID does not belong to that user.", []interface{}{})
			return
		}
		links, err = twocloud.GetLinksByDevice(device, roleFlag, before, after, count)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
	} else {
		links, err = twocloud.GetLinksByUser(user, roleFlag, before, after, count)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
	}
	Respond(w, r, http.StatusOK, "Successfully retrieved a list of links", links)
	return
}

func sendLink(w http.ResponseWriter, r *twocloud.RequestBundle) {
}

func getLink(w http.ResponseWriter, r *twocloud.RequestBundle) {
}

func updateLink(w http.ResponseWriter, r *twocloud.RequestBundle) {
}

func deleteLink(w http.ResponseWriter, r *twocloud.RequestBundle) {
}

func auditLink(w http.ResponseWriter, r *twocloud.RequestBundle) {
}
