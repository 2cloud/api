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
	if username == "" {
		Respond(w, http.StatusBadRequest, "Missing username.", []interface{}{MissingParam("username")})
		return
	}
	var after, before uint64
	var err error
	afterstr := r.URL.Query().Get("after")
	if afterstr != "" {
		after, err = strconv.ParseUint(afterstr, 10, 64)
		if err != nil {
			Respond(w, http.StatusBadRequest, "Invalid after ID.", []interface{}{InvalidFormat("after")})
			return
		}
	}
	beforestr := r.URL.Query().Get("before")
	if beforestr != "" {
		before, err = strconv.ParseUint(beforestr, 10, 64)
		if err != nil {
			Respond(w, http.StatusBadRequest, "Invalid before ID.", []interface{}{InvalidFormat("before")})
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
	var notifications []twocloud.Notification
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	deviceID := r.URL.Query().Get(":device")
	if deviceID != "" {
		id, err := strconv.ParseUint(deviceID, 10, 64)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusBadRequest, "Invalid device ID.", []interface{}{InvalidFormat("device")})
			return
		}
		device, err := b.getDevice(twocloud.ID(id))
		if err != nil {
			if err == UnauthorisedAccessAttempt {
				Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{AccessDenied("")})
				return
			}
			if err == twocloud.DeviceNotFoundError {
				Respond(w, http.StatusNotFound, "Device not found.", []interface{}{NotFound("device")})
				return
			}
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
			return
		}
		if device.UserID != user.ID {
			Respond(w, http.StatusBadRequest, "That device ID does not belong to that user.", []interface{}{WrongOwner("device")})
			return
		}
		notifications, err = b.Persister.GetNotificationsByDevice(device, twocloud.ID(before), twocloud.ID(after), count)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
			return
		}
	} else {
		notifications, err = b.Persister.GetNotificationsByUser(user, twocloud.ID(before), twocloud.ID(after), count)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
			return
		}
	}
	Respond(w, http.StatusOK, "Successfully retrieved a list of notifications", []interface{}{notifications})
	return
}

func getNotification(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Missing username.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	notificationIDstr := r.URL.Query().Get(":notification")
	if notificationIDstr == "" {
		Respond(w, http.StatusBadRequest, "Missing notification ID.", []interface{}{MissingParam("id")})
		return
	}
	notificationID, err := strconv.ParseUint(notificationIDstr, 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid notification ID", []interface{}{InvalidFormat("id")})
		return
	}
	notification, err := b.Persister.GetNotification(twocloud.ID(notificationID))
	if err != nil {
		if err == twocloud.NotificationNotFoundError {
			Respond(w, http.StatusNotFound, err.Error(), []interface{}{NotFound("id")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	if notification.DestinationType == "user" && notification.Destination != user.ID {
		Respond(w, http.StatusBadRequest, "That notification doesn't belong to that user.", []interface{}{WrongOwner("id")})
		return
	} else if notification.DestinationType == "device" {
		device, err := b.getDevice(notification.Destination)
		if err != nil {
			if err == UnauthorisedAccessAttempt {
				Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{AccessDenied("")})
				return
			}
			if err == twocloud.DeviceNotFoundError {
				Respond(w, http.StatusNotFound, "Device not found.", []interface{}{NotFound("device")})
				return
			}
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
			return
		}
		if device.UserID != user.ID {
			Respond(w, http.StatusBadRequest, "That notification does not belong to that user.", []interface{}{WrongOwner("device")})
			return
		}
	}
	Respond(w, http.StatusOK, "Successfully retrieved notification information", []interface{}{notification})
	return
}

func sendNotification(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	if !b.AuthUser.IsAdmin {
		Respond(w, http.StatusForbidden, "You don't have permission to send notifications.", []interface{}{AccessDenied("")})
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
	notifications := []twocloud.Notification{}
	for pos, not := range request.Notifications {
		if not.Nature == nil {
			Respond(w, http.StatusBadRequest, "Nature must be specified for each notification.", []interface{}{MissingParamOnItem("notification.nature", pos)})
			return
		}
		if not.Body == nil {
			Respond(w, http.StatusBadRequest, "Body must be specified for each notification.", []interface{}{MissingParamOnItem("notification.body", pos)})
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
		user, err := b.getUser(username)
		if err != nil {
			if err == UnauthorisedAccessAttempt {
				Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{AccessDenied("")})
				return
			}
			if err == twocloud.UserNotFoundError {
				Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
				return
			}
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
			return
		}
		deviceIDstr := r.URL.Query().Get(":device")
		if deviceIDstr != "" {
			deviceID, err := strconv.ParseUint(deviceIDstr, 10, 64)
			if err != nil {
				b.Persister.Log.Error(err.Error())
				Respond(w, http.StatusBadRequest, "Invalid device ID", []interface{}{InvalidFormat("device")})
				return
			}
			device, err := b.getDevice(twocloud.ID(deviceID))
			if err != nil {
				if err == UnauthorisedAccessAttempt {
					Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{AccessDenied("")})
					return
				}
				if err == twocloud.DeviceNotFoundError {
					Respond(w, http.StatusNotFound, "Device not found.", []interface{}{NotFound("device")})
					return
				}
				Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
				return
			}
			if device.UserID != user.ID {
				Respond(w, http.StatusBadRequest, "Specified device does not belong to specified user.", []interface{}{WrongOwner("device")})
				return
			}
			notifications, err := b.Persister.SendNotificationsToDevice(device, notifications)
			if err != nil {
				b.Persister.Log.Error(err.Error())
				Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
				return
			}
			Respond(w, http.StatusCreated, "Successfully created notifications", []interface{}{notifications})
			return
		}
		notifications, err := b.Persister.SendNotificationsToUser(user, notifications)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
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
		Respond(w, http.StatusBadRequest, err.Error(), []interface{}{InvalidValue("broadcast_filter")})
		return
	} else if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusCreated, "Successfully created notifications", []interface{}{notifications})
	return
}

func markNotificationRead(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Missing username.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	id := r.URL.Query().Get(":notification")
	if id == "" {
		Respond(w, http.StatusBadRequest, "Missing notification ID.", []interface{}{MissingParam("id")})
		return
	}
	notificationID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid notification ID", []interface{}{InvalidFormat("id")})
		return
	}
	notification, err := b.Persister.GetNotification(twocloud.ID(notificationID))
	if err != nil {
		if err == twocloud.NotificationNotFoundError {
			Respond(w, http.StatusNotFound, err.Error(), []interface{}{NotFound("id")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	if notification.DestinationType == "user" && notification.Destination != user.ID {
		Respond(w, http.StatusBadRequest, "That notification doesn't belong to that user.", []interface{}{WrongOwner("id")})
		return
	} else if notification.DestinationType == "device" {
		device, err := b.getDevice(notification.Destination)
		if err != nil {
			if err == UnauthorisedAccessAttempt {
				Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{AccessDenied("")})
				return
			}
			if err == twocloud.DeviceNotFoundError {
				Respond(w, http.StatusNotFound, "Device not found.", []interface{}{NotFound("device")})
				return
			}
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
			return
		}
		if device.UserID != user.ID {
			Respond(w, http.StatusBadRequest, "That notification does not belong to that user.", []interface{}{WrongOwner("id")})
			return
		}
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
	if request.Notification == nil {
		Respond(w, http.StatusBadRequest, "Must include a notification in the request body.", []interface{}{MissingParam("notification")})
		return
	} else if request.Notification.Unread == nil {
		Respond(w, http.StatusBadRequest, "Unread cannot be nil.", []interface{}{MissingParam("notification.unread")})
		return
	} else if *request.Notification.Unread == true {
		Respond(w, http.StatusBadRequest, "Unread cannot be true.", []interface{}{InvalidValue("notification.unread")})
		return
	}
	notification.Unread = *request.Notification.Unread
	notification, err = b.Persister.MarkNotificationRead(notification)
	if err != nil {
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully updated the notification", []interface{}{notification})
	return
}

func deleteNotification(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Username missing.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	id := r.URL.Query().Get(":notification")
	if id == "" {
		Respond(w, http.StatusBadRequest, "Missing notification ID.", []interface{}{MissingParam("id")})
		return
	}
	notificationID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid notification ID", []interface{}{InvalidFormat("id")})
		return
	}
	notification, err := b.Persister.GetNotification(twocloud.ID(notificationID))
	if err != nil {
		if err == twocloud.NotificationNotFoundError {
			Respond(w, http.StatusNotFound, err.Error(), []interface{}{NotFound("id")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	if notification.DestinationType == "user" && notification.Destination != user.ID {
		Respond(w, http.StatusBadRequest, "That notification doesn't belong to that user.", []interface{}{WrongOwner("id")})
		return
	} else if notification.DestinationType == "device" {
		device, err := b.getDevice(notification.Destination)
		if err != nil {
			if err == UnauthorisedAccessAttempt {
				Respond(w, http.StatusUnauthorized, "You don't have access to that user's notifications.", []interface{}{AccessDenied("")})
				return
			}
			if err == twocloud.DeviceNotFoundError {
				Respond(w, http.StatusNotFound, "Device not found.", []interface{}{NotFound("device")})
				return
			}
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
			return
		}
		if device.UserID != user.ID {
			Respond(w, http.StatusBadRequest, "That notification does not belong to that user.", []interface{}{WrongOwner("id")})
			return
		}
	}
	err = b.Persister.DeleteNotification(notification)
	if err != nil {
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully deleted the notification", []interface{}{notification})
	return
}
