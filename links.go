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
	if username == "" {
		Respond(w, http.StatusBadRequest, "Missing username in URL.", []interface{}{MissingParam("username")})
		return
	}
	role := r.URL.Query().Get("role")
	roleFlag := twocloud.RoleEither
	if role == "sender" {
		roleFlag = twocloud.RoleSender
	} else if role == "receiver" {
		roleFlag = twocloud.RoleReceiver
	} else if role != "" {
		Respond(w, http.StatusBadRequest, "Invalid role.", []interface{}{InvalidValue("role")})
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
		} else {
			Respond(w, http.StatusBadRequest, "Invalid count.", []interface{}{InvalidValue("count")})
			return
		}
	}
	var links []twocloud.Link
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{AccessDenied("")})
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
		id, err := strconv.ParseUint(r.URL.Query().Get(":device"), 10, 64)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Invalid device ID.", []interface{}{InvalidFormat("device")})
			return
		}
		device, err := b.getDevice(twocloud.ID(id))
		if err != nil {
			if err == UnauthorisedAccessAttempt {
				Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{AccessDenied("")})
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
		links, err = b.Persister.GetLinksByDevice(device, roleFlag, twocloud.ID(before), twocloud.ID(after), count)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
			return
		}
	} else {
		links, err = b.Persister.GetLinksByUser(user, roleFlag, twocloud.ID(before), twocloud.ID(after), count)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
			return
		}
	}
	Respond(w, http.StatusOK, "Successfully retrieved a list of links", []interface{}{links})
	return
}

func sendLinks(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Username not set.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{AccessDenied("")})
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
	if deviceID == "" {
		Respond(w, http.StatusBadRequest, "Device ID not set.", []interface{}{MissingParam("device")})
		return
	}
	id, err := strconv.ParseUint(deviceID, 10, 64)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusBadRequest, "Invalid device ID.", []interface{}{InvalidFormat("device")})
		return
	}
	device, err := b.getDevice(twocloud.ID(id))
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{AccessDenied("")})
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
	links := []twocloud.Link{}
	for pos, link := range request.Links {
		if link.URL == nil || link.URL.Address == nil {
			Respond(w, http.StatusBadRequest, "The address field must be specified.", []interface{}{MissingParamOnItem("link.url.address", pos)})
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
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
	}
	Respond(w, http.StatusCreated, "Successfully created links", []interface{}{links})
	return
}

func getLink(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Username must be specified.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	devID := r.URL.Query().Get(":device")
	if devID == "" {
		Respond(w, http.StatusBadRequest, "Device must be specified.", []interface{}{MissingParam("device")})
		return
	}
	id, err := strconv.ParseUint(devID, 10, 64)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusBadRequest, "Invalid device ID.", []interface{}{InvalidFormat("device")})
		return
	}
	device, err := b.getDevice(twocloud.ID(id))
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{AccessDenied("")})
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
	linkIDStr := r.URL.Query().Get(":link")
	if linkIDStr == "" {
		Respond(w, http.StatusBadRequest, "Link must be specified.", []interface{}{MissingParam("id")})
		return
	}
	linkID, err := strconv.ParseUint(linkIDStr, 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid link ID", []interface{}{InvalidFormat("id")})
		return
	}
	link, err := b.Persister.GetLink(twocloud.ID(linkID))
	if err != nil {
		if err == twocloud.LinkNotFoundError {
			Respond(w, http.StatusNotFound, "Link not found.", []interface{}{NotFound("link")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	if link.Sender != device.ID && link.Receiver != device.ID {
		Respond(w, http.StatusBadRequest, "Link does not belong to specified device.", []interface{}{WrongOwner("link")})
		return
	}
	Respond(w, http.StatusOK, "Successfully retrieved link information", []interface{}{link})
	return
}

func updateLink(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Username not specified.", []interface{}{MissingParam("username")})
		return
	}
	deviceID := r.URL.Query().Get(":device")
	if deviceID == "" {
		Respond(w, http.StatusBadRequest, "Device ID not specified.", []interface{}{MissingParam("device")})
		return
	}
	id, err := strconv.ParseUint(deviceID, 10, 64)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusBadRequest, "Invalid device ID.", []interface{}{InvalidFormat("device")})
		return
	}
	linkIDstr := r.URL.Query().Get(":link")
	if linkIDstr == "" {
		Respond(w, http.StatusBadRequest, "Link ID not specified.", []interface{}{MissingParam("id")})
	}
	linkID, err := strconv.ParseUint(linkIDstr, 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid link ID", []interface{}{InvalidFormat("id")})
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
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	device, err := b.getDevice(twocloud.ID(id))
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{AccessDenied("")})
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
	link, err := b.Persister.GetLink(twocloud.ID(linkID))
	if err != nil {
		if err == twocloud.LinkNotFoundError {
			Respond(w, http.StatusNotFound, "Link not found.", []interface{}{NotFound("link")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	if link.SenderUser != device.UserID && link.ReceiverUser != device.UserID {
		Respond(w, http.StatusBadRequest, "That link does not belong to that device.", []interface{}{WrongOwner("link")})
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
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully retrieved link information", []interface{}{link})
	return
}

func deleteLink(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Username missing.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{AccessDenied("")})
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
	if deviceID == "" {
		Respond(w, http.StatusBadRequest, "Device ID missing.", []interface{}{MissingParam("device")})
	}
	id, err := strconv.ParseUint(deviceID, 10, 64)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusBadRequest, "Invalid device ID.", []interface{}{InvalidFormat("device")})
		return
	}
	device, err := b.getDevice(twocloud.ID(id))
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's links.", []interface{}{AccessDenied("")})
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
	linkIDstr := r.URL.Query().Get(":link")
	if linkIDstr == "" {
		Respond(w, http.StatusBadRequest, "Missing link ID.", []interface{}{MissingParam("id")})
		return
	}
	linkID, err := strconv.ParseUint(linkIDstr, 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid link ID", []interface{}{InvalidFormat("id")})
		return
	}
	link, err := b.Persister.GetLink(twocloud.ID(linkID))
	if err != nil {
		if err == twocloud.LinkNotFoundError {
			Respond(w, http.StatusNotFound, "Link not found.", []interface{}{NotFound("id")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	if link.SenderUser != device.UserID && link.ReceiverUser != device.UserID {
		Respond(w, http.StatusBadRequest, "Link does not belong to the specified device.", []interface{}{WrongOwner("id")})
		return
	}
	err = b.Persister.DeleteLink(link)
	if err != nil {
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully deleted the link", []interface{}{link})
	return
}
