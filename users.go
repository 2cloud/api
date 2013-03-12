package main

import (
	"get.2cloud.org/twocloud"
	"net/http"
	"strconv"
	"time"
)

type user struct {
	Username *string `json:"username,omitempty"`
	Email    *string `json:"email,omitempty"`
	Name     *struct {
		Given  *string `json:"given,omitempty"`
		Family *string `json:"family,omitempty"`
	} `json:"name,omitempty"`
	Admin             *bool `json:"admin,omitempty"`
	ReceiveNewsletter *bool `json:"receive_newsletter,omitempty"`
}

type emailVerification struct {
	Code string `json:"code"`
}

func getUsers(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	if !b.AuthUser.IsAdmin {
		Respond(w, http.StatusForbidden, "You don't have access to the user list.", []interface{}{})
		return
	}
	active_afterstr := r.URL.Query().Get("active_after")
	active_beforestr := r.URL.Query().Get("active_before")
	joined_afterstr := r.URL.Query().Get("joined_after")
	joined_beforestr := r.URL.Query().Get("joined_before")
	var joined_before, joined_after, active_before, active_after time.Time
	countstr := r.URL.Query().Get("count")
	count := 20
	var err error
	if countstr != "" {
		count, err = strconv.Atoi(countstr)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusBadRequest, "Invalid count param.", []interface{}{})
			return
		}
	}
	if count > 100 {
		count = 100
	}
	if active_afterstr != "" {
		active_after, err = time.Parse(time.RFC3339, active_afterstr)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusBadRequest, "Invalid active_after value.", []interface{}{})
			return
		}
	}
	if active_beforestr != "" {
		active_before, err = time.Parse(time.RFC3339, active_beforestr)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusBadRequest, "Invalid active_before value.", []interface{}{})
			return
		}
	}
	if active_beforestr != "" || active_afterstr != "" {
		users, err := b.Persister.GetUsersByActivity(count, active_after, active_before)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
			return
		}
		Respond(w, http.StatusOK, "Successfully retrieved a list of users", []interface{}{users})
		return
	}
	if joined_afterstr != "" {
		joined_after, err = time.Parse(time.RFC3339, joined_afterstr)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusBadRequest, "Invalid joined_after value.", []interface{}{})
			return
		}
	}
	if joined_beforestr != "" {
		joined_before, err = time.Parse(time.RFC3339, joined_beforestr)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusBadRequest, "Invalid joined_before value.", []interface{}{})
			return
		}
	}
	users, err := b.Persister.GetUsersByJoinDate(count, joined_after, joined_before)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{users})
		return
	}
	Respond(w, http.StatusOK, "Successfully retrieved a list of users", []interface{}{users})
	return
}

func createUser(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
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
	if request.Account == nil || request.Account.ID == 0 {
		Respond(w, http.StatusBadRequest, "Account ID must be specified.", []interface{}{})
		return
	}
	if request.User == nil {
		Respond(w, http.StatusBadRequest, "Must include a user object.", []interface{}{})
		return
	}
	account, err := b.Persister.GetAccountByID(request.Account.ID)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	if account.ID == 0 {
		Respond(w, http.StatusBadRequest, "Invalid Account ID", []interface{}{})
		return
	}
	if account.UserID != 0 {
		Respond(w, http.StatusConflict, "Account already registered.", []interface{}{})
		return
	}
	if request.User.Username == nil {
		Respond(w, http.StatusBadRequest, "Username must be specified.", []interface{}{})
		return
	}
	if request.User.Email == nil {
		Respond(w, http.StatusBadRequest, "Email must be specified.", []interface{}{})
		return
	}
	var given_name, family_name *string
	if request.User.Name != nil {
		given_name = request.User.Name.Given
		family_name = request.User.Name.Family
	}
	newsletter := false
	if request.User.ReceiveNewsletter != nil {
		newsletter = *request.User.ReceiveNewsletter
	}
	user, err := b.Persister.Register(*request.User.Username, *request.User.Email, given_name, family_name, true, false, newsletter)
	if err != nil {
		if err == twocloud.MissingEmailError {
			Respond(w, http.StatusBadRequest, "Email must be specified.", []interface{}{})
			return
		} else if err == twocloud.UsernameTakenError {
			Respond(w, http.StatusConflict, "Username taken.", []interface{}{})
			return
		} else if err == twocloud.InvalidUsernameCharacterError || err == twocloud.InvalidUsernameLengthError {
			Respond(w, http.StatusBadRequest, err.Error(), []interface{}{})
			return
		}
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	err = b.Persister.AssociateUserWithAccount(account, user.ID)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	_, err = b.Persister.CreateSubscription(user.ID, twocloud.ID(0), "", false)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	setLastModified(w, user.LastActive)
	Respond(w, http.StatusCreated, "Successfully created a user account", []interface{}{user})
	return
}

func getUser(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user.", []interface{}{})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	setLastModified(w, user.LastActive)
	Respond(w, http.StatusOK, "Successfully retrieved user information.", []interface{}{user})
	return
}

func updateUser(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user.", []interface{}{})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
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
	if request.User == nil {
		Respond(w, http.StatusBadRequest, "Request must include user.", []interface{}{})
		return
	}
	if !b.AuthUser.IsAdmin && request.User.Admin != nil {
		Respond(w, http.StatusForbidden, "You need to be an administrator before you can grant or remove admin privileges.", []interface{}{})
		return
	}
	if request.User.Email != nil && *request.User.Email == "" {
		Respond(w, http.StatusBadRequest, "Email must be specified or omitted.", []interface{}{})
		return
	}
	err = b.Persister.UpdateUser(&user, request.User.Email, request.User.Name.Given, request.User.Name.Family, request.User.ReceiveNewsletter)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	if request.User.Admin != nil {
		if *request.User.Admin && !user.IsAdmin {
			err = b.Persister.MakeAdmin(&user)
			if err != nil {
				b.Persister.Log.Error(err.Error())
				Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
				return
			}
		} else if !*request.User.Admin && user.IsAdmin {
			err = b.Persister.StripAdmin(&user)
			if err != nil {
				b.Persister.Log.Error(err.Error())
				Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
				return
			}
		}
	}
	Respond(w, http.StatusOK, "Successfully updated the user.", []interface{}{user})
	return
}

func deleteUser(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user.", []interface{}{})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	err = b.Persister.DeleteUser(user)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, http.StatusOK, "Successfully deleted the user.", []interface{}{user})
	return
}

func getUserAccounts(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's accounts.", []interface{}{})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	accounts, err := b.Persister.GetAccountsByUser(user.ID)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	Respond(w, http.StatusOK, "Successfully retrieved a list of accounts", []interface{}{accounts})
	return
}

func resetSecret(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user.", []interface{}{})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	err = b.Persister.ResetSecret(&user)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	Respond(w, http.StatusOK, "Successfully reset secret.", []interface{}{user})
	return
}

func verifyEmail(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user.", []interface{}{})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{})
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
	if request.EmailVerification == nil || request.EmailVerification.Code == "" {
		Respond(w, http.StatusBadRequest, "Code must be set.", []interface{}{})
		return
	}
	err = b.Persister.VerifyEmail(&user, request.EmailVerification.Code)
	if err == twocloud.InvalidConfirmationCodeError {
		Respond(w, http.StatusBadRequest, "Invalid confirmation code.", []interface{}{})
		return
	} else if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	Respond(w, http.StatusOK, "Successfully verified email address", []interface{}{user})
	return
}
