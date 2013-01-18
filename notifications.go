package main

import (
	"encoding/json"
	"get.2cloud.org/twocloud"
	"io/ioutil"
	"net/http"
	"strconv"
)

type notificationReq struct {
	Notifications []twocloud.Notification   `json:"notifications,omitempty"`
	Filter        *twocloud.BroadcastFilter `json:"broadcast_filter,omitempty"`
}

func getNotifications(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	var after, before uint64
	var err error
	afterstr := r.URL.Query().Get("after")
	if afterstr != "" {
		after, err = strconv.ParseUint(afterstr, 10, 64)
		if err != nil {
			Respond(w, http.StatusBadRequest, "Invalid after ID.", []interface{}{})
			return
		}
	}
	beforestr := r.URL.Query().Get("before")
	if beforestr != "" {
		before, err = strconv.ParseUint(beforestr, 10, 64)
		if err != nil {
			Respond(w, http.StatusBadRequest, "Invalid before ID.", []interface{}{})
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
	var notifications []twocloud.Notification
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	deviceID := r.URL.Query().Get(":device")
	if deviceID != "" {
		id, err := strconv.ParseUint(r.URL.Query().Get(":device"), 10, 64)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusBadRequest, "Invalid device ID.", []interface{}{})
			return
		}
		device, err := b.getDevice(id)
		if err != nil {
			if err == UnauthorisedAccessAttempt {
				Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{})
				return
			}
			if err == twocloud.DeviceNotFoundError {
				Respond(w, http.StatusNotFound, "Device not found.", []interface{}{})
				return
			}
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
		if device.UserID != user.ID {
			Respond(w, http.StatusBadRequest, "That device ID does not belong to that user.", []interface{}{})
			return
		}
		notifications, err = b.Persister.GetNotificationsByDevice(device, before, after, count)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
	} else {
		notifications, err = b.Persister.GetNotificationsByUser(user, before, after, count)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
	}
	Respond(w, http.StatusOK, "Successfully retrieved a list of notifications", []interface{}{notifications})
	return
}

func getNotification(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	notificationID, err := strconv.ParseUint(r.URL.Query().Get(":notification"), 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid notification ID", []interface{}{})
		return
	}
	notification, err := b.Persister.GetNotification(notificationID)
	if err != nil {
		if err == twocloud.NotificationNotFoundError {
			Respond(w, http.StatusInternalServerError, err.Error(), []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	if notification.DestinationType == "user" && notification.Destination != user.ID {
		Respond(w, http.StatusBadRequest, "That notification doesn't belong to that user.", []interface{}{})
		return
	} else if notification.DestinationType == "device" {
		device, err := b.getDevice(notification.Destination)
		if err != nil {
			if err == UnauthorisedAccessAttempt {
				Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{})
				return
			}
			if err == twocloud.DeviceNotFoundError {
				Respond(w, http.StatusNotFound, "Device not found.", []interface{}{})
				return
			}
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
		if device.UserID != user.ID {
			Respond(w, http.StatusBadRequest, "That notification does not belong to that user.", []interface{}{})
			return
		}
	}
	Respond(w, http.StatusOK, "Successfully retrieved notification information", []interface{}{notification})
	return
}
func sendNotification(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	if !b.AuthUser.IsAdmin {
		Respond(w, http.StatusForbidden, "You don't have permission to send notifications.", []interface{}{})
		return
	}
	var req notificationReq
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
	username := r.URL.Query().Get(":username")
	if username != "" {
		deviceIDstr := r.URL.Query().Get(":device")
		if deviceIDstr != "" {
			deviceID, err := strconv.ParseUint(deviceIDstr, 10, 64)
			if err != nil {
				b.Persister.Log.Error(err.Error())
				Respond(w, http.StatusBadRequest, "Invalid device ID", []interface{}{})
				return
			}
			device, err := b.getDevice(deviceID)
			if err != nil {
				if err == UnauthorisedAccessAttempt {
					Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{})
					return
				}
				if err == twocloud.DeviceNotFoundError {
					Respond(w, http.StatusNotFound, "Device not found.", []interface{}{})
					return
				}
				Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
				return
			}
			notifications, err := b.Persister.SendNotificationsToDevice(device, req.Notifications)
			if err != nil {
				b.Persister.Log.Error(err.Error())
				Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
				return
			}
			Respond(w, http.StatusCreated, "Successfully created notifications", []interface{}{notifications})
			return
		}
		user, err := b.getUser(username)
		if err != nil {
			if err == UnauthorisedAccessAttempt {
				Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{})
				return
			}
			if err == twocloud.UserNotFoundError {
				Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
				return
			}
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}

		notifications, err := b.Persister.SendNotificationsToUser(user, req.Notifications)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
		Respond(w, http.StatusCreated, "Successfully created notifications", []interface{}{notifications})
		return
	}
	notifications, err := b.Persister.BroadcastNotifications(req.Notifications, req.Filter)
	if err == twocloud.InvalidBroadcastFilter {
		Respond(w, http.StatusBadRequest, err.Error(), []interface{}{})
		return
	} else if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, http.StatusCreated, "Successfully created notifications", []interface{}{notifications})
	return
}

func markNotificationRead(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	notificationID, err := strconv.ParseUint(r.URL.Query().Get(":notification"), 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid notification ID", []interface{}{})
		return
	}
	notification, err := b.Persister.GetNotification(notificationID)
	if err != nil {
		if err == twocloud.NotificationNotFoundError {
			Respond(w, http.StatusNotFound, err.Error(), []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	if notification.DestinationType == "user" && notification.Destination != user.ID {
		Respond(w, http.StatusBadRequest, "That notification doesn't belong to that user.", []interface{}{})
		return
	} else if notification.DestinationType == "device" {
		device, err := b.getDevice(notification.Destination)
		if err != nil {
			if err == UnauthorisedAccessAttempt {
				Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{})
				return
			}
			if err == twocloud.DeviceNotFoundError {
				Respond(w, http.StatusNotFound, "Device not found.", []interface{}{})
				return
			}
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
		if device.UserID != user.ID {
			Respond(w, http.StatusBadRequest, "That notification does not belong to that user.", []interface{}{})
			return
		}
	}
	var req twocloud.Notification
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
	if req.Unread {
		Respond(w, http.StatusBadRequest, "Unread cannot be true.", []interface{}{})
		return
	}
	notification.Unread = req.Unread
	notification, err = b.Persister.MarkNotificationRead(notification)
	if err != nil {
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, http.StatusOK, "Successfully updated the notification", []interface{}{notification})
	return
}

func deleteNotification(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	notificationID, err := strconv.ParseUint(r.URL.Query().Get(":notification"), 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid notification ID", []interface{}{})
		return
	}
	notification, err := b.Persister.GetNotification(notificationID)
	if err != nil {
		if err == twocloud.NotificationNotFoundError {
			Respond(w, http.StatusNotFound, err.Error(), []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	if notification.DestinationType == "user" && notification.Destination != user.ID {
		Respond(w, http.StatusBadRequest, "That notification doesn't belong to that user.", []interface{}{})
		return
	} else if notification.DestinationType == "device" {
		device, err := b.getDevice(notification.Destination)
		if err != nil {
			if err == UnauthorisedAccessAttempt {
				Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{})
				return
			}
			if err == twocloud.DeviceNotFoundError {
				Respond(w, http.StatusNotFound, "Device not found.", []interface{}{})
				return
			}
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
		if device.UserID != user.ID {
			Respond(w, http.StatusBadRequest, "That notification does not belong to that user.", []interface{}{})
			return
		}
	}
	err = b.Persister.DeleteNotification(notification)
	if err != nil {
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, http.StatusOK, "Successfully deleted the notification", []interface{}{notification})
	return
}

func auditNotification(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
}
