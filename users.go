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
		Respond(w, http.StatusForbidden, "You don't have access to the user list.", []interface{}{AccessDenied("")})
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
			Respond(w, http.StatusBadRequest, "Invalid count param.", []interface{}{InvalidFormat("count")})
			return
		}
	}
	if count > 100 {
		Respond(w, http.StatusBadRequest, "Count must be 100 or less.", []interface{}{TooLong("count")})
		return
	} else if count < 0 {
		Respond(w, http.StatusBadRequest, "Count must be greater than 0.", []interface{}{TooShort("count")})
		return
	}
	if active_afterstr != "" {
		active_after, err = time.Parse(time.RFC3339, active_afterstr)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusBadRequest, "Invalid active_after value.", []interface{}{InvalidFormat("active_after")})
			return
		}
	}
	if active_beforestr != "" {
		active_before, err = time.Parse(time.RFC3339, active_beforestr)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusBadRequest, "Invalid active_before value.", []interface{}{InvalidFormat("active_before")})
			return
		}
	}
	if active_beforestr != "" || active_afterstr != "" {
		users, err := b.Persister.GetUsersByActivity(count, active_after, active_before)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
			return
		}
		Respond(w, http.StatusOK, "Successfully retrieved a list of users", []interface{}{users})
		return
	}
	if joined_afterstr != "" {
		joined_after, err = time.Parse(time.RFC3339, joined_afterstr)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusBadRequest, "Invalid joined_after value.", []interface{}{InvalidFormat("joined_after")})
			return
		}
	}
	if joined_beforestr != "" {
		joined_before, err = time.Parse(time.RFC3339, joined_beforestr)
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusBadRequest, "Invalid joined_before value.", []interface{}{InvalidFormat("joined_before")})
			return
		}
	}
	users, err := b.Persister.GetUsersByJoinDate(count, joined_after, joined_before)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
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
			Respond(w, http.StatusBadRequest, "Error decoding request.", []interface{}{BadRequestFormat("")})
		} else {
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		}
		return
	}
	if request.Account == nil || request.Account.ID == 0 {
		Respond(w, http.StatusBadRequest, "Account ID must be specified.", []interface{}{MissingParam("account.id")})
		return
	}
	if request.User == nil {
		Respond(w, http.StatusBadRequest, "Must include a user object.", []interface{}{MissingParam("user")})
		return
	}
	account, err := b.Persister.GetAccountByID(request.Account.ID)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	if account.ID == 0 {
		Respond(w, http.StatusBadRequest, "Invalid Account ID", []interface{}{InvalidValue("account.id")})
		return
	}
	if account.UserID != 0 {
		Respond(w, http.StatusConflict, "Account already registered.", []interface{}{AlreadyInUse("account")})
		return
	}
	if request.User.Username == nil {
		Respond(w, http.StatusBadRequest, "Username must be specified.", []interface{}{MissingParam("user.username")})
		return
	}
	if request.User.Email == nil {
		Respond(w, http.StatusBadRequest, "Email must be specified.", []interface{}{MissingParam("user.email")})
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
	email_unconfirmed := (*request.User.Email != account.Email) || !account.EmailVerified
	user, err := b.Persister.Register(*request.User.Username, *request.User.Email, given_name, family_name, email_unconfirmed, false, newsletter)
	if err != nil {
		if err == twocloud.MissingEmailError {
			Respond(w, http.StatusBadRequest, "Email must be specified.", []interface{}{MissingParam("user.email")})
			return
		} else if err == twocloud.UsernameTakenError {
			Respond(w, http.StatusConflict, "Username taken.", []interface{}{AlreadyInUse("user.username")})
			return
		} else if err == twocloud.InvalidUsernameCharacterError {
			Respond(w, http.StatusBadRequest, err.Error(), []interface{}{InvalidValue("user.username")})
			return
		} else if err == twocloud.InvalidUsernameLengthShortError {
			Respond(w, http.StatusBadRequest, err.Error(), []interface{}{TooShort("user.username")})
			return
		} else if err == twocloud.InvalidUsernameLengthLongError {
			Respond(w, http.StatusBadRequest, err.Error(), []interface{}{TooLong("user.username")})
			return
		}
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	err = b.Persister.AssociateUserWithAccount(account, user.ID)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	setLastModified(w, user.LastActive)
	Respond(w, http.StatusCreated, "Successfully created a user account", []interface{}{user})
	return
}

func getUser(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Missing username.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	setLastModified(w, user.LastActive)
	Respond(w, http.StatusOK, "Successfully retrieved user information.", []interface{}{user})
	return
}

func updateUser(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Missing username.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user.", []interface{}{AccessDenied("")})
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
	if request.User == nil {
		Respond(w, http.StatusBadRequest, "Request must include user.", []interface{}{MissingParam("user")})
		return
	}
	if !b.AuthUser.IsAdmin && request.User.Admin != nil {
		Respond(w, http.StatusForbidden, "You need to be an administrator before you can grant or remove admin privileges.", []interface{}{AccessDenied("user.admin")})
		return
	}
	if request.User.Email != nil && *request.User.Email == "" {
		Respond(w, http.StatusBadRequest, "Email must be specified or omitted.", []interface{}{MissingParam("user.email")})
		return
	}
	err = b.Persister.UpdateUser(&user, request.User.Email, request.User.Name.Given, request.User.Name.Family, request.User.ReceiveNewsletter)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	if request.User.Admin != nil {
		if *request.User.Admin && !user.IsAdmin {
			err = b.Persister.MakeAdmin(&user)
			if err != nil {
				b.Persister.Log.Error(err.Error())
				Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
				return
			}
		} else if !*request.User.Admin && user.IsAdmin {
			err = b.Persister.StripAdmin(&user)
			if err != nil {
				b.Persister.Log.Error(err.Error())
				Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
				return
			}
		}
	}
	Respond(w, http.StatusOK, "Successfully updated the user.", []interface{}{user})
	return
}

func deleteUser(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Missing username.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	err = b.Persister.DeleteUser(user)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully deleted the user.", []interface{}{user})
	return
}

func getUserAccounts(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Username must be specified.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user's accounts.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	accounts, err := b.Persister.GetAccountsByUser(user.ID)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully retrieved a list of accounts", []interface{}{accounts})
	return
}

func resetSecret(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Missing username.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("user")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	err = b.Persister.ResetSecret(&user)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully reset secret.", []interface{}{user})
	return
}

func verifyEmail(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if username == "" {
		Respond(w, http.StatusBadRequest, "Missing username.", []interface{}{MissingParam("username")})
		return
	}
	user, err := b.getUser(username)
	if err != nil {
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that user.", []interface{}{AccessDenied("")})
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
	if request.EmailVerification == nil || request.EmailVerification.Code == "" {
		Respond(w, http.StatusBadRequest, "Code must be set.", []interface{}{MissingParam("email_verification.code")})
		return
	}
	err = b.Persister.VerifyEmail(&user, request.EmailVerification.Code)
	if err == twocloud.InvalidConfirmationCodeError {
		Respond(w, http.StatusBadRequest, "Invalid confirmation code.", []interface{}{InvalidValue("email_verification.code")})
		return
	} else if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully verified email address", []interface{}{user})
	return
}
