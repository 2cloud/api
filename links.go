package main

import (
	"encoding/json"
	"get.2cloud.org/twocloud"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

type LinksReq struct {
	Links []twocloud.Link `json:"links"`
}

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
		links, err = r.GetLinksByDevice(device, roleFlag, before, after, count)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
	} else {
		links, err = r.GetLinksByUser(user, roleFlag, before, after, count)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
			return
		}
	}
	Respond(w, r, http.StatusOK, "Successfully retrieved a list of links", []interface{}{links})
	return
}

func sendLinks(w http.ResponseWriter, r *twocloud.RequestBundle) {
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
	deviceID, err := strconv.ParseUint(r.Request.URL.Query().Get(":device"), 10, 64)
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
	var req LinksReq
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
	links := []twocloud.Link{}
	for _, link := range req.Links {
		if link.URL == nil || link.URL.Address == "" {
			Respond(w, r, http.StatusBadRequest, "The address field must be specified.", []interface{}{})
			return
		}
		link.Sender = r.Device
		link.Receiver = device
		link.Unread = true
		links = append(links, link)
	}
	links, err = r.AddLinks(links)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
	}
	Respond(w, r, http.StatusCreated, "Successfully created links", []interface{}{links})
	return
}

func getLink(w http.ResponseWriter, r *twocloud.RequestBundle) {
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
	deviceID, err := strconv.ParseUint(r.Request.URL.Query().Get(":device"), 10, 64)
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
	linkID, err := strconv.ParseUint(r.Request.URL.Query().Get(":link"), 10, 64)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, "Invalid link ID", []interface{}{})
		return
	}
	link, err := r.GetLink(linkID)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, r, http.StatusOK, "Successfully retrieved link information", []interface{}{link})
	return
}

func updateLink(w http.ResponseWriter, r *twocloud.RequestBundle) {
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
	deviceID, err := strconv.ParseUint(r.Request.URL.Query().Get(":device"), 10, 64)
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
	linkID, err := strconv.ParseUint(r.Request.URL.Query().Get(":link"), 10, 64)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, "Invalid link ID", []interface{}{})
		return
	}
	link, err := r.GetLink(linkID)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	var req twocloud.Link
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
	if req.URL != nil {
		Respond(w, r, http.StatusBadRequest, "URL cannot be modified.", []interface{}{})
		return
	}
	unread := link.Unread
	comment := link.Comment
	if device.ID == link.Sender.ID {
		comment = req.Comment
	} else if device.ID == link.Receiver.ID {
		unread = req.Unread
	}
	link, err = r.UpdateLink(link, unread, comment)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, r, http.StatusOK, "Successfully retrieved link information", []interface{}{link})
	return
}

func deleteLink(w http.ResponseWriter, r *twocloud.RequestBundle) {
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
	deviceID, err := strconv.ParseUint(r.Request.URL.Query().Get(":device"), 10, 64)
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
	linkID, err := strconv.ParseUint(r.Request.URL.Query().Get(":link"), 10, 64)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, "Invalid link ID", []interface{}{})
		return
	}
	link, err := r.GetLink(linkID)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	err = r.DeleteLink(link)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, r, http.StatusOK, "Successfully deleted the link", []interface{}{link})
	return
}

func auditLink(w http.ResponseWriter, r *twocloud.RequestBundle) {
}
