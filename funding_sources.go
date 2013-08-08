package main

import (
	"get.2cloud.org/twocloud"
	"net/http"
	"strconv"
	"strings"
)

func getFundingSources(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Username must be specified.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's funding sources.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	fs, err := b.Persister.GetFundingSourcesByUser(user)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{("ActOfGod")})
		return
	}
	Respond(w, http.StatusOK, "Successfully retrieved funding sources", []interface{}{fs})
	return
}

func getFundingSource(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Username must be specified.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's funding sources.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	fsID := r.URL.Query().Get(":id")
	if fsID == "" {
		Respond(w, http.StatusBadRequest, "Missing funding source ID.", []interface{}{MissingParam("id")})
		return
	}
	id, err := strconv.ParseUint(fsID, 10, 64)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusBadRequest, "Invalid funding source ID", []interface{}{InvalidFormat("id")})
		return
	}
	fsType := r.URL.Query().Get(":provider")
	if fsType == "" {
		Respond(w, http.StatusBadRequest, "Missing funding source provider.", []interface{}{MissingParam("provider")})
		return
	}
	fsType = strings.ToLower(fsType)
	if !twocloud.IsValidProvider(fsType) {
		Respond(w, http.StatusBadRequest, "Not a valid funding source provider.", []interface{}{InvalidValue("provider")})
		return
	}
	fs := twocloud.FundingSources{}
	switch fsType {
	case "stripe":
		source, err := b.Persister.GetStripeSource(twocloud.ID(id))
		if err != nil {
			if err == twocloud.FundingSourceNotFoundError {
				Respond(w, http.StatusNotFound, "Funding source not found.", []interface{}{NotFound("id")})
				return
			}
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
			return
		}
		if source.UserID != user.ID {
			Respond(w, http.StatusBadRequest, "Funding source does not belong to specified user.", []interface{}{WrongOwner("id")})
			return
		}
		fs.Stripe = []twocloud.Stripe{source}
	}
	Respond(w, http.StatusOK, "Successfully retrieved funding source.", []interface{}{fs})
}

func addFundingSource(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Username must be specified.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's funding sources.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
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
	if request.FundingSources == nil {
		Respond(w, http.StatusBadRequest, "Missing funding sources object.", []interface{}{MissingParam("funding_sources")})
		return
	}
	if len(request.FundingSources.Stripe) < 1 {
		Respond(w, http.StatusBadRequest, "Funding source not supplied.", []interface{}{TooShort("funding_sources")})
		return
	}
	if len(request.FundingSources.Stripe) > 1 {
		Respond(w, http.StatusBadRequest, "Too many funding sources supplied.", []interface{}{TooLong("funding_sources")})
		return
	}
	if request.FundingSources.Stripe[0].RemoteID == "" {
		Respond(w, http.StatusBadRequest, "Missing remote_id.", []interface{}{MissingParam("remote_id")})
		return
	}
	s, err := b.Persister.AddStripeSource(request.FundingSources.Stripe[0].RemoteID, request.FundingSources.Stripe[0].GetNickname(), user.ID)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully created funding source.", []interface{}{twocloud.FundingSources{Stripe: []twocloud.Stripe{s}}})
	return
}

func updateFundingSource(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Username must be specified.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's funding sources.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	fsID := r.URL.Query().Get(":id")
	if fsID == "" {
		Respond(w, http.StatusBadRequest, "Missing funding source ID.", []interface{}{MissingParam("id")})
		return
	}
	id, err := strconv.ParseUint(fsID, 10, 64)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusBadRequest, "Invalid funding source ID", []interface{}{InvalidFormat("id")})
		return
	}
	fsType := r.URL.Query().Get(":provider")
	if fsType == "" {
		Respond(w, http.StatusBadRequest, "Missing funding source provider.", []interface{}{MissingParam("provider")})
		return
	}
	fsType = strings.ToLower(fsType)
	if !twocloud.IsValidProvider(fsType) {
		Respond(w, http.StatusBadRequest, "Not a valid funding source provider.", []interface{}{InvalidValue("provider")})
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
	if request.FundingSources == nil {
		Respond(w, http.StatusBadRequest, "Missing funding sources object.", []interface{}{MissingParam("funding_sources")})
		return
	}
	resp := twocloud.FundingSources{}
	switch fsType {
	case "stripe":
		source, err := b.Persister.GetStripeSource(twocloud.ID(id))
		if err != nil {
			if err == twocloud.FundingSourceNotFoundError {
				Respond(w, http.StatusNotFound, "Funding source not found.", []interface{}{NotFound("id")})
				return
			}
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
			return
		}
		if source.UserID != user.ID {
			Respond(w, http.StatusBadRequest, "Funding source does not belong to specified user.", []interface{}{WrongOwner("id")})
			return
		}
		if len(request.FundingSources.Stripe) < 1 {
			Respond(w, http.StatusBadRequest, "Funding source not supplied.", []interface{}{TooShort("funding_sources")})
			return
		}
		if len(request.FundingSources.Stripe) > 1 {
			Respond(w, http.StatusBadRequest, "Too many funding sources supplied.", []interface{}{TooLong("funding_sources")})
			return
		}
		var remote_id *string
		if request.FundingSources.Stripe[0].RemoteID == "" {
			remote_id = nil
		} else {
			remote_id = &request.FundingSources.Stripe[0].RemoteID
		}
		err = b.Persister.UpdateStripeSource(&source, remote_id, request.FundingSources.Stripe[0].Nickname)
		if err != nil {
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
			return
		}
		resp.Stripe = []twocloud.Stripe{source}
	}
	Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{resp})
}

func deleteFundingSource(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Username must be specified.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's funding sources.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	fsID := r.URL.Query().Get(":id")
	if fsID == "" {
		Respond(w, http.StatusBadRequest, "Missing funding source ID.", []interface{}{MissingParam("id")})
		return
	}
	id, err := strconv.ParseUint(fsID, 10, 64)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusBadRequest, "Invalid funding source ID", []interface{}{InvalidFormat("id")})
		return
	}
	fsType := r.URL.Query().Get(":provider")
	if fsType == "" {
		Respond(w, http.StatusBadRequest, "Missing funding source provider.", []interface{}{MissingParam("provider")})
		return
	}
	fsType = strings.ToLower(fsType)
	if !twocloud.IsValidProvider(fsType) {
		Respond(w, http.StatusBadRequest, "Not a valid funding source provider.", []interface{}{InvalidValue("provider")})
	}
	switch fsType {
	case "stripe":
		source, err := b.Persister.GetStripeSource(twocloud.ID(id))
		if err != nil {
			if err == twocloud.FundingSourceNotFoundError {
				Respond(w, http.StatusNotFound, "Funding source not found.", []interface{}{NotFound("id")})
				return
			}
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
			return
		}
		if source.UserID != user.ID {
			Respond(w, http.StatusBadRequest, "Funding source does not belong to specified user.", []interface{}{WrongOwner("id")})
			return
		}
		err = b.Persister.DeleteStripeSource(source)
		if err != nil {
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
			return
		}
		Respond(w, http.StatusOK, "Successfully removed funding source.", []interface{}{twocloud.FundingSources{Stripe: []twocloud.Stripe{source}}})
		return
	}
}
