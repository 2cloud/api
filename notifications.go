package main

import (
	"get.2cloud.org/twocloud"
	"net/http"
	"strconv"
	"strings"
)

type notification struct {
	Nature *string `json:"nature,omitempty"`
	Body   *string `json:"body,omitempty"`
	Unread *bool   `json:"unread,omitempty"`
}

type broadcastFilter struct {
	Targets    string   `json:"targets,omitempty"`
	ClientType []string `json:"client_type,omitempty"`
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
		device, err := b.getDevice(twocloud.ID(id))
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
		notifications, err = b.Persister.GetNotificationsByDevice(device, twocloud.ID(before), twocloud.ID(after), count)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
	} else {
		notifications, err = b.Persister.GetNotificationsByUser(user, twocloud.ID(before), twocloud.ID(after), count)
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
	notification, err := b.Persister.GetNotification(twocloud.ID(notificationID))
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
	notifications := []twocloud.Notification{}
	for _, not := range request.Notifications {
		if not.Nature == nil {
			Respond(w, http.StatusBadRequest, "Nature must be specified for each notification.", []interface{}{})
			return
		}
		if not.Body == nil {
			Respond(w, http.StatusBadRequest, "Body must be specified for each notification.", []interface{}{})
			return
		}
		unread := false
		if not.Unread != nil {
			unread = *not.Unread
		}
		notification := twocloud.Notification{
			Nature: strings.TrimSpace(*not.Nature),
			Unread: unread,
			Body:   strings.TrimSpace(*not.Body),
		}
		notifications = append(notifications, notification)
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
			device, err := b.getDevice(twocloud.ID(deviceID))
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
			notifications, err := b.Persister.SendNotificationsToDevice(device, notifications)
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

		notifications, err := b.Persister.SendNotificationsToUser(user, notifications)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
		Respond(w, http.StatusCreated, "Successfully created notifications", []interface{}{notifications})
		return
	}
	var bf *twocloud.BroadcastFilter
	if request.BroadcastFilter != nil {
		bf.Targets = request.BroadcastFilter.Targets
		bf.ClientType = request.BroadcastFilter.ClientType
	}
	notifications, err = b.Persister.BroadcastNotifications(notifications, bf)
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
	notification, err := b.Persister.GetNotification(twocloud.ID(notificationID))
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
	if request.Notification == nil {
		Respond(w, http.StatusBadRequest, "Must include a notification in the request body.", []interface{}{})
		return
	} else if request.Notification.Unread == nil {
		Respond(w, http.StatusBadRequest, "Unread cannot be nil.", []interface{}{})
		return
	} else if *request.Notification.Unread == true {
		Respond(w, http.StatusBadRequest, "Unread cannot be true.", []interface{}{})
		return
	}
	notification.Unread = *request.Notification.Unread
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
	notification, err := b.Persister.GetNotification(twocloud.ID(notificationID))
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
