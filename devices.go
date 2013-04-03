package main

import (
	"get.2cloud.org/twocloud"
	"net/http"
	"strconv"
	"strings"
)

type pusher struct {
	Key *string `json:"key,omitempty"`
}

type pushers struct {
	GCM        *pusher `json:"gcm,omitempty"`
	WebSockets *pusher `json:"websockets,omitempty"`
}

type device struct {
	Name       *string  `json:"name,omitempty"`
	ClientType *string  `json:"client_type,omitempty"`
	Pushers    *pushers `json:"pushers,omitempty"`
}

func getDevices(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Username must be specified.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's devices.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	devices, err := b.Persister.GetDevicesByUser(user)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully retrieved a list of devices", []interface{}{devices})
	return
}

func getDevice(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Missing username.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's devices.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusUnauthorized, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	deviceID := r.URL.Query().Get(":device")
	if deviceID == "" {
		Respond(w, http.StatusBadRequest, "Missing device ID.", []interface{}{MissingParam("id")})
		return
	}
	id, err := strconv.ParseUint(deviceID, 10, 64)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusBadRequest, "Invalid device ID.", []interface{}{InvalidFormat("id")})
		return
	}
	device, err := b.getDevice(twocloud.ID(id))
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's devices.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.DeviceNotFoundError {
			Respond(w, http.StatusNotFound, "Device not found.", []interface{}{NotFound("id")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	if device.UserID != user.ID {
		Respond(w, http.StatusBadRequest, "That device ID does not belong to that user.", []interface{}{WrongOwner("id")})
		return
	}
	Respond(w, http.StatusOK, "Successfully retrieved device information", []interface{}{device})
	return
}

func newDevice(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Missing username.", []interface{}{MissingParam("username")})
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
	if request.Device == nil {
		Respond(w, http.StatusBadRequest, "Must supply device.", []interface{}{MissingParam("device")})
		return
	}
	if request.Device.Name == nil {
		Respond(w, http.StatusBadRequest, "Name must be specified.", []interface{}{MissingParam("device.name")})
		return
	}
	if request.Device.ClientType == nil {
		Respond(w, http.StatusBadRequest, "Client type must be specified.", []interface{}{MissingParam("device.client_type")})
		return
	}
	clientType := strings.ToLower(*request.Device.ClientType)
	request.Device.ClientType = &clientType
	tmpdevice := twocloud.Device{ClientType: *request.Device.ClientType}
	if !tmpdevice.ValidClientType() {
		Respond(w, http.StatusBadRequest, "Invalid client type.", []interface{}{InvalidValue("device.client_type")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's devices.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	var gcm_key *string
	if request.Device.Pushers != nil && request.Device.Pushers.GCM != nil {
		gcm_key = request.Device.Pushers.GCM.Key
	}
	device, err := b.Persister.AddDevice(*request.Device.Name, *request.Device.ClientType, r.RemoteAddr, gcm_key, user)
	if err != nil {
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusCreated, "Successfully created a device", []interface{}{device})
	return
}

func updateDevice(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
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
	if request.Device == nil {
		Respond(w, http.StatusBadRequest, "Must supply device.", []interface{}{MissingParam("device")})
		return
	}
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Must supply username.", []interface{}{MissingParam("username")})
		return
	}
	deviceID := r.URL.Query().Get(":device")
	if deviceID == "" {
		Respond(w, http.StatusBadRequest, "Must supply device ID.", []interface{}{MissingParam("id")})
		return
	}
	id, err := strconv.ParseUint(deviceID, 10, 64)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusBadRequest, "Invalid device ID.", []interface{}{InvalidFormat("id")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's devices.", []interface{}{AccessDenied("")})
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
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's devices.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.DeviceNotFoundError {
			Respond(w, http.StatusNotFound, "Device not found.", []interface{}{NotFound("id")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	if device.UserID != user.ID {
		Respond(w, http.StatusBadRequest, "The specified device does not belong to the specified user", []interface{}{WrongOwner("id")})
		return
	}
	var gcm_key *string
	if request.Device.Pushers != nil && request.Device.Pushers.GCM != nil {
		gcm_key = request.Device.Pushers.GCM.Key
	}
	err = b.Persister.UpdateDevice(&device, request.Device.Name, request.Device.ClientType, gcm_key)
	if err != nil {
		if err == twocloud.InvalidClientType {
			Respond(w, http.StatusBadRequest, "Invalid client_type.", []interface{}{InvalidValue("device.client_type")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusCreated, "Successfully updated the device", []interface{}{device})
	return
}

func deleteDevice(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Username is required.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's devices.", []interface{}{AccessDenied("")})
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
		Respond(w, http.StatusBadRequest, "Device ID is required.", []interface{}{MissingParam("id")})
		return
	}
	id, err := strconv.ParseUint(deviceID, 10, 64)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusBadRequest, "Invalid device ID.", []interface{}{InvalidFormat("id")})
		return
	}
	device, err := b.getDevice(twocloud.ID(id))
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's devices.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.DeviceNotFoundError {
			Respond(w, http.StatusNotFound, "Device not found.", []interface{}{NotFound("id")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	if device.UserID != user.ID {
		Respond(w, http.StatusBadRequest, "That device ID does not belong to that user.", []interface{}{WrongOwner("id")})
		return
	}
	err = b.Persister.DeleteDevice(device)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully deleted the device", []interface{}{device})
	return
}
