package main

import (
	"get.2cloud.org/twocloud"
	"net/http"
	"secondbit.org/ruid"
	"strconv"
	"strings"
)

func getNotifications(w http.ResponseWriter, r *twocloud.RequestBundle) {
	username := r.Request.URL.Query().Get(":username")
	user := r.AuthUser
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
	var notifications []twocloud.Notification
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
		notifications, err = r.GetNotificationsByDevice(device, before, after, count)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
	} else {
		notifications, err = r.GetNotificationsByUser(user, before, after, count)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
	}
	Respond(w, r, http.StatusOK, "Successfully retrieved a list of notifications", []interface{}{notifications})
	return
}

func getNotification(w http.ResponseWriter, r *twocloud.RequestBundle) {
	username := r.Request.URL.Query().Get(":username")
	user := r.AuthUser
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
	deviceID, err := ruid.RUIDFromString(r.Request.URL.Query().Get(":device"))
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusBadRequest, "Invalid device ID", []interface{}{})
		return
	}
	device, err := r.GetDevice(deviceID)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	if device.UserID != user.ID {
		Respond(w, r, http.StatusBadRequest, "That device ID does not belong to that user.", []interface{}{})
		return
	}
	notificationID, err := ruid.RUIDFromString(r.Request.URL.Query().Get(":notification"))
	if err != nil {
		Respond(w, r, http.StatusBadRequest, "Invalid notification ID", []interface{}{})
		return
	}
	notification, err := r.GetNotification(notificationID)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, r, http.StatusOK, "Successfully retrieved notification information", []interface{}{notification})
	return
}

func sendNotification(w http.ResponseWriter, r *twocloud.RequestBundle) {
}

func broadcastNotification(w http.ResponseWriter, r *twocloud.RequestBundle) {
}

func markNotificationRead(w http.ResponseWriter, r *twocloud.RequestBundle) {
}

func deleteNotification(w http.ResponseWriter, r *twocloud.RequestBundle) {
}

func auditNotification(w http.ResponseWriter, r *twocloud.RequestBundle) {
}
