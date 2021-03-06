package main

import (
	"encoding/json"
	"get.2cloud.org/twocloud"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

type notificationReq struct {
	Notifications []twocloud.Notification   `json:"notifications,omitempty"`
	Filter        *twocloud.BroadcastFilter `json:"broadcast_filter,omitempty"`
}

func getNotifications(w http.ResponseWriter, r *twocloud.RequestBundle) {
	username := r.Request.URL.Query().Get(":username")
	user := r.AuthUser
	var after, before uint64
	var err error
	afterstr := r.Request.URL.Query().Get("after")
	if afterstr != "" {
		after, err = strconv.ParseUint(afterstr, 10, 64)
		if err != nil {
			Respond(w, r, http.StatusBadRequest, "Invalid after ID.", []interface{}{})
			return
		}
	}
	beforestr := r.Request.URL.Query().Get("before")
	if beforestr != "" {
		before, err = strconv.ParseUint(beforestr, 10, 64)
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
			Respond(w, r, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{})
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
		id, err := strconv.ParseUint(r.Request.URL.Query().Get(":device"), 10, 64)
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
			Respond(w, r, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{})
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
	notificationID, err := strconv.ParseUint(r.Request.URL.Query().Get(":notification"), 10, 64)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, "Invalid notification ID", []interface{}{})
		return
	}
	notification, err := r.GetNotification(notificationID)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	if notification.DestinationType == "user" && notification.Destination != user.ID {
		Respond(w, r, http.StatusBadRequest, "That notification doesn't belong to that user.", []interface{}{})
		return
	} else if notification.DestinationType == "device" {
		device, err := r.GetDevice(notification.Destination)
		if err != nil {
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
		if device.UserID != user.ID {
			Respond(w, r, http.StatusBadRequest, "That notification does not belong to that user.", []interface{}{})
			return
		}
	}
	Respond(w, r, http.StatusOK, "Successfully retrieved notification information", []interface{}{notification})
	return
}
func sendNotification(w http.ResponseWriter, r *twocloud.RequestBundle) {
	if !r.AuthUser.IsAdmin {
		Respond(w, r, http.StatusForbidden, "You don't have permission to send notifications.", []interface{}{})
		return
	}
	var req notificationReq
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
	username := r.Request.URL.Query().Get(":username")
	if username != "" {
		deviceIDstr := r.Request.URL.Query().Get(":device")
		if deviceIDstr != "" {
			deviceID, err := strconv.ParseUint(deviceIDstr, 10, 64)
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
			notifications, err := r.SendNotificationsToDevice(device, req.Notifications)
			if err != nil {
				r.Log.Error(err.Error())
				Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
				return
			}
			Respond(w, r, http.StatusCreated, "Successfully created notifications", []interface{}{notifications})
			return
		}
		id, err := r.GetUserID(username)
		if err != nil {
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
		notifications, err := r.SendNotificationsToUser(user, req.Notifications)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
		Respond(w, r, http.StatusCreated, "Successfully created notifications", []interface{}{notifications})
		return
	}
	notifications, err := r.BroadcastNotifications(req.Notifications, req.Filter)
	if err == twocloud.InvalidBroadcastFilter {
		Respond(w, r, http.StatusBadRequest, err.Error(), []interface{}{})
		return
	} else if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, r, http.StatusCreated, "Successfully created notifications", []interface{}{notifications})
	return
}

func markNotificationRead(w http.ResponseWriter, r *twocloud.RequestBundle) {
	username := r.Request.URL.Query().Get(":username")
	user := r.AuthUser
	var err error
	if strings.ToLower(username) != strings.ToLower(r.AuthUser.Username) {
		if !r.AuthUser.IsAdmin {
			Respond(w, r, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{})
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
	notificationID, err := strconv.ParseUint(r.Request.URL.Query().Get(":notification"), 10, 64)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, "Invalid notification ID", []interface{}{})
		return
	}
	notification, err := r.GetNotification(notificationID)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	if notification.DestinationType == "user" && notification.Destination != user.ID {
		Respond(w, r, http.StatusBadRequest, "That notification doesn't belong to that user.", []interface{}{})
		return
	} else if notification.DestinationType == "device" {
		device, err := r.GetDevice(notification.Destination)
		if err != nil {
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
		if device.UserID != user.ID {
			Respond(w, r, http.StatusBadRequest, "That notification does not belong to that user.", []interface{}{})
			return
		}
	}
	var req twocloud.Notification
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
	if req.Unread {
		Respond(w, r, http.StatusBadRequest, "Unread cannot be true.", []interface{}{})
		return
	}
	notification.Unread = req.Unread
	notification, err = r.MarkNotificationRead(notification)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, r, http.StatusOK, "Successfully updated the notification", []interface{}{notification})
	return
}

func deleteNotification(w http.ResponseWriter, r *twocloud.RequestBundle) {
	username := r.Request.URL.Query().Get(":username")
	user := r.AuthUser
	if strings.ToLower(username) != strings.ToLower(r.AuthUser.Username) {
		if !r.AuthUser.IsAdmin {
			Respond(w, r, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{})
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
	notificationID, err := strconv.ParseUint(r.Request.URL.Query().Get(":notification"), 10, 64)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, "Invalid notification ID", []interface{}{})
		return
	}
	notification, err := r.GetNotification(notificationID)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	if notification.DestinationType == "user" && notification.Destination != user.ID {
		Respond(w, r, http.StatusBadRequest, "That notification doesn't belong to that user.", []interface{}{})
		return
	} else if notification.DestinationType == "device" {
		device, err := r.GetDevice(notification.Destination)
		if err != nil {
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
		if device.UserID != user.ID {
			Respond(w, r, http.StatusBadRequest, "That notification does not belong to that user.", []interface{}{})
			return
		}
	}
	err = r.DeleteNotification(notification)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, r, http.StatusOK, "Successfully deleted the notification", []interface{}{notification})
	return
}

func auditNotification(w http.ResponseWriter, r *twocloud.RequestBundle) {
}
