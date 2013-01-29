package main

import (
	"get.2cloud.org/twocloud"
	"net/http"
	"strconv"
)

type urlData struct {
	Address *string `json:"address,omitempty"`
}

type link struct {
	URL     *urlData `json:"url,omitempty"`
	Unread  *bool    `json:"unread,omitempty"`
	Comment *string  `json:"comment,omitempty"`
}

func getLinks(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	role := r.URL.Query().Get("role")
	roleFlag := twocloud.RoleEither
	if role == "sender" {
		roleFlag = twocloud.RoleSender
	} else if role == "receiver" {
		roleFlag = twocloud.RoleReceiver
	}
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
	var links []twocloud.Link
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{})
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
			Respond(w, http.StatusInternalServerError, "Invalid device ID.", []interface{}{})
			return
		}
		device, err := b.getDevice(twocloud.ID(id))
		if err != nil {
			if err == UnauthorisedAccessAttempt {
				Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{})
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
		links, err = b.Persister.GetLinksByDevice(device, roleFlag, twocloud.ID(before), twocloud.ID(after), count)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
	} else {
		links, err = b.Persister.GetLinksByUser(user, roleFlag, twocloud.ID(before), twocloud.ID(after), count)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
	}
	Respond(w, http.StatusOK, "Successfully retrieved a list of links", []interface{}{links})
	return
}

func sendLinks(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	id, err := strconv.ParseUint(r.URL.Query().Get(":device"), 10, 64)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusBadRequest, "Invalid device ID.", []interface{}{})
		return
	}
	device, err := b.getDevice(twocloud.ID(id))
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{})
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
	links := []twocloud.Link{}
	for _, link := range request.Links {
		if link.URL == nil || link.URL.Address == nil {
			Respond(w, http.StatusBadRequest, "The address field must be specified.", []interface{}{})
			return
		}
		unread := true
		if link.Unread != nil {
			unread = *link.Unread
		}
		newLink := twocloud.Link{
			URL: &twocloud.URL{
				Address: *link.URL.Address,
			},
			Unread:       unread,
			Sender:       b.AuthDevice.ID,
			Receiver:     device.ID,
			ReceiverUser: device.UserID,
			Comment:      link.Comment,
		}
		links = append(links, newLink)
	}
	links, err = b.Persister.AddLinks(links)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
	}
	Respond(w, http.StatusCreated, "Successfully created links", []interface{}{links})
	return
}

func getLink(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	id, err := strconv.ParseUint(r.URL.Query().Get(":device"), 10, 64)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusBadRequest, "Invalid device ID.", []interface{}{})
		return
	}
	device, err := b.getDevice(twocloud.ID(id))
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{})
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
	linkID, err := strconv.ParseUint(r.URL.Query().Get(":link"), 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid link ID", []interface{}{})
		return
	}
	link, err := b.Persister.GetLink(twocloud.ID(linkID))
	if err != nil {
		if err == twocloud.LinkNotFoundError {
			Respond(w, http.StatusNotFound, "Link not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, http.StatusOK, "Successfully retrieved link information", []interface{}{link})
	return
}

func updateLink(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	id, err := strconv.ParseUint(r.URL.Query().Get(":device"), 10, 64)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusBadRequest, "Invalid device ID.", []interface{}{})
		return
	}
	linkID, err := strconv.ParseUint(r.URL.Query().Get(":link"), 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid link ID", []interface{}{})
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
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	device, err := b.getDevice(twocloud.ID(id))
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{})
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
	link, err := b.Persister.GetLink(twocloud.ID(linkID))
	if err != nil {
		if err == twocloud.LinkNotFoundError {
			Respond(w, http.StatusNotFound, "Link not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	unread := request.Link.Unread
	comment := request.Link.Comment
	if device.ID != link.Sender {
		comment = nil
	} else if device.ID != link.Receiver {
		unread = nil
	}
	link, err = b.Persister.UpdateLink(link, unread, comment)
	if err != nil {
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, http.StatusOK, "Successfully retrieved link information", []interface{}{link})
	return
}

func deleteLink(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	id, err := strconv.ParseUint(r.URL.Query().Get(":device"), 10, 64)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusBadRequest, "Invalid device ID.", []interface{}{})
		return
	}
	device, err := b.getDevice(twocloud.ID(id))
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{})
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
	linkID, err := strconv.ParseUint(r.URL.Query().Get(":link"), 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid link ID", []interface{}{})
		return
	}
	link, err := b.Persister.GetLink(twocloud.ID(linkID))
	if err != nil {
		if err == twocloud.LinkNotFoundError {
			Respond(w, http.StatusNotFound, "Link not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	// TODO: check link ownership
	err = b.Persister.DeleteLink(link)
	if err != nil {
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, http.StatusOK, "Successfully deleted the link", []interface{}{link})
	return
}

func auditLink(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
}
