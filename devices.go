package main

import (
	"get.2cloud.org/twocloud"
	"net/http"
	"secondbit.org/ruid"
	"strings"
)

func getDevices(w http.ResponseWriter, r *twocloud.RequestBundle) {
	username := r.Request.URL.Query().Get(":username")
	user := r.AuthUser
	if strings.ToLower(username) != strings.ToLower(r.AuthUser.Username) {
		if !r.AuthUser.IsAdmin {
			Respond(w, r, http.StatusUnauthorized, "You don't have access to that user's devices.", []interface{}{})
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
	devices, err := r.GetDevicesByUser(user)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, r, http.StatusOK, "Successfully retrieved a list of devices", []interface{}{devices})
	return
}

func newDevice(w http.ResponseWriter, r *twocloud.RequestBundle) {	username := r.Request.URL.Query().Get(":username")
	user := r.AuthUser
	if strings.ToLower(username) != strings.ToLower(r.AuthUser.Username) {
		if !r.AuthUser.IsAdmin {
			Respond(w, r, http.StatusUnauthorized, "You don't have access to that user's devices.", []interface{}{})
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
	Respond(w, r, http.StatusOK, "Successfully retrieved device information", []interface{}{device})
	return
}

func getDevice(w http.ResponseWriter, r *twocloud.RequestBundle) {
}

func updateDevice(w http.ResponseWriter, r *twocloud.RequestBundle) {
}

func deleteDevice(w http.ResponseWriter, r *twocloud.RequestBundle) {
}
