package main

import (
	"encoding/json"
	"get.2cloud.org/twocloud"
	"io/ioutil"
	"net/http"
	"secondbit.org/ruid"
	"strconv"
	"strings"
	"time"
)

type accountAndUserRequest struct {
	Account twocloud.Account `json:"account"`
	User    twocloud.User    `json:"user"`
}

type modifyUserRequest struct {
	User   twocloud.User `json:"user"`
	Fields []string      `json:"fields"`
}

type verifyEmailRequest struct {
	Code string `json:"code"`
}

func getUsers(w http.ResponseWriter, r *twocloud.RequestBundle) {
	if !r.AuthUser.IsAdmin {
		Respond(w, r, http.StatusForbidden, "You don't have access to the user list.", []interface{}{})
		return
	}
	active_afterstr := r.Request.URL.Query().Get("active_after")
	active_beforestr := r.Request.URL.Query().Get("active_before")
	joined_afterstr := r.Request.URL.Query().Get("joined_after")
	joined_beforestr := r.Request.URL.Query().Get("joined_before")
	var joined_before, joined_after, active_before, active_after time.Time
	countstr := r.Request.URL.Query().Get("count")
	count := 20
	var err error
	if countstr != "" {
		count, err = strconv.Atoi(countstr)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusBadRequest, "Invalid count param.", []interface{}{})
			return
		}
	}
	if count > 100 {
		count = 100
	}
	if active_afterstr != "" {
		active_after, err = time.Parse(time.RFC3339, active_afterstr)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusBadRequest, "Invalid active_after value.", []interface{}{})
			return
		}
	}
	if active_beforestr != "" {
		active_before, err = time.Parse(time.RFC3339, active_beforestr)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusBadRequest, "Invalid active_before value.", []interface{}{})
			return
		}
	}
	if active_beforestr != "" || active_afterstr != "" {
		users, err := r.GetUsersByActivity(count, active_after, active_before)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
			return
		}
		Respond(w, r, http.StatusOK, "Successfully retrieved a list of users", []interface{}{users})
		return
	}
	if joined_afterstr != "" {
		joined_after, err = time.Parse(time.RFC3339, joined_afterstr)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusBadRequest, "Invalid joined_after value.", []interface{}{})
			return
		}
	}
	if joined_beforestr != "" {
		joined_before, err = time.Parse(time.RFC3339, joined_beforestr)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusBadRequest, "Invalid joined_before value.", []interface{}{})
			return
		}
	}
	users, err := r.GetUsersByJoinDate(count, joined_after, joined_before)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{users})
		return
	}
	Respond(w, r, http.StatusOK, "Successfully retrieved a list of users", []interface{}{users})
	return
}

func createUser(w http.ResponseWriter, r *twocloud.RequestBundle) {
	var req accountAndUserRequest
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
	if req.Account.ID == ruid.RUID(0) {
		Respond(w, r, http.StatusBadRequest, "Account ID must be specified.", []interface{}{})
		return
	}
	account, err := r.GetAccountByID(req.Account.ID)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	if account.ID == ruid.RUID(0) {
		Respond(w, r, http.StatusBadRequest, "Invalid Account ID", []interface{}{})
		return
	}
	if account.UserID != ruid.RUID(0) {
		Respond(w, r, http.StatusConflict, "Account already registered.", []interface{}{})
		return
	}
	if req.User.Username == "" {
		Respond(w, r, http.StatusBadRequest, "Username must be specified.", []interface{}{})
		return
	}
	user, err := r.Register(req.User.Username, req.User.Email, req.User.Name.Given, req.User.Name.Family, true, false)
	if err != nil {
		if err == twocloud.MissingEmailError {
			Respond(w, r, http.StatusBadRequest, "Email must be specified.", []interface{}{})
			return
		} else if err == twocloud.UsernameTakenError {
			Respond(w, r, http.StatusConflict, "Username taken.", []interface{}{})
			return
		} else if err == twocloud.InvalidUsernameCharacterError || err == twocloud.InvalidUsernameLengthError {
			Respond(w, r, http.StatusBadRequest, err.Error(), []interface{}{})
			return
		}
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	err = r.AssociateUserWithAccount(account, user.ID)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	setLastModified(w, user.LastActive)
	Respond(w, r, http.StatusCreated, "Successfully created a user account", []interface{}{user})
	return
}

func getUser(w http.ResponseWriter, r *twocloud.RequestBundle) {
	username := r.Request.URL.Query().Get(":username")
	includeSub := r.Request.URL.Query().Get("include_subscription") == "1"
	if username == "" {
		Respond(w, r, http.StatusNotFound, "User not found.", []interface{}{})
		return
	}
	if strings.ToLower(username) == strings.ToLower(r.AuthUser.Username) {
		user := r.AuthUser
		user.Subscription = nil
		elems := []interface{}{user}
		if includeSub {
			elems = append(elems, r.AuthUser.Subscription)
		}
		setLastModified(w, user.LastActive)
		Respond(w, r, http.StatusOK, "Successfully retrieved user information", elems)
		return
	}
	if !r.AuthUser.IsAdmin {
		Respond(w, r, http.StatusForbidden, "You don't have access to that user's account.", []interface{}{})
		return
	}
	id, err := r.GetUserID(username)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	user, err := r.GetUser(id)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	sub := user.Subscription
	user.Subscription = nil
	elems := []interface{}{user}
	if includeSub {
		elems = append(elems, sub)
	}
	setLastModified(w, user.LastActive)
	Respond(w, r, http.StatusOK, "Successfully retrieved user information", []interface{}{user})
	return
}

func updateUser(w http.ResponseWriter, r *twocloud.RequestBundle) {
	var req modifyUserRequest
	user := r.AuthUser
	username := r.Request.URL.Query().Get(":username")
	if strings.ToLower(username) != strings.ToLower(r.AuthUser.Username) {
		if !r.AuthUser.IsAdmin {
			Respond(w, r, http.StatusForbidden, "You don't have access to that user's account.", []interface{}{})
			return
		}
		id, err := r.GetUserID(username)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
			return
		}
		user, err = r.GetUser(id)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
			return
		}
	}
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
	email := user.Email
	given_name := user.Name.Given
	family_name := user.Name.Family
	name_changed := false
	admin := false
	for _, field := range req.Fields {
		switch field {
		case "email":
			if req.User.Email == "" {
				Respond(w, r, http.StatusBadRequest, "Email cannot be empty.", []interface{}{})
				return
			}
			email = req.User.Email
			break
		case "name.given":
			given_name = req.User.Name.Given
			name_changed = true
			break
		case "name.family":
			family_name = req.User.Name.Family
			name_changed = true
			break
		case "admin":
			if !r.AuthUser.IsAdmin {
				Respond(w, r, http.StatusForbidden, "You don't have the ability to grant or revoke admin status.", []interface{}{})
				return
			}
			admin = true
			break
		}
	}
	err = r.UpdateUser(user, email, given_name, family_name, name_changed)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	user.Email = email
	if name_changed {
		user.Name.Given = given_name
		user.Name.Family = family_name
	}
	if admin {
		if req.User.IsAdmin && !user.IsAdmin {
			err = r.MakeAdmin(user)
			if err != nil {
				r.Log.Error(err.Error())
				Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
				return
			}
			user.IsAdmin = true
		} else if !req.User.IsAdmin && user.IsAdmin {
			err = r.StripAdmin(user)
			if err != nil {
				r.Log.Error(err.Error())
				Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
				return
			}
			user.IsAdmin = false
		}
	}
	Respond(w, r, http.StatusOK, "Successfully updated the user account", []interface{}{user})
	return
}

func deleteUser(w http.ResponseWriter, r *twocloud.RequestBundle) {
	user := r.AuthUser
	username := r.Request.URL.Query().Get(":username")
	if strings.ToLower(username) != strings.ToLower(r.AuthUser.Username) {
		if !r.AuthUser.IsAdmin {
			Respond(w, r, http.StatusForbidden, "You don't have access to that user.", []interface{}{})
			return
		}
		id, err := r.GetUserID(username)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
			return
		}
		user, err = r.GetUser(id)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
			return
		}
	}
	err := r.DeleteUser(user)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error", []interface{}{})
		return
	}
	Respond(w, r, http.StatusOK, "Successfully deleted the user", []interface{}{user})
	return
}

func getUserAccounts(w http.ResponseWriter, r *twocloud.RequestBundle) {
	user := r.AuthUser
	username := r.Request.URL.Query().Get(":username")
	if strings.ToLower(username) != strings.ToLower(r.AuthUser.Username) {
		if !r.AuthUser.IsAdmin {
			Respond(w, r, http.StatusForbidden, "You don't have access to that user's accounts.", []interface{}{})
			return
		}
		id, err := r.GetUserID(username)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
			return
		}
		user, err = r.GetUser(id)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
			return
		}
	}
	accounts, err := r.GetAccountsByUser(user)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	Respond(w, r, http.StatusOK, "Successfully retrieved a list of accounts", []interface{}{accounts})
	return
}

func resetSecret(w http.ResponseWriter, r *twocloud.RequestBundle) {
	user := r.AuthUser
	username := r.Request.URL.Query().Get(":username")
	if strings.ToLower(username) != strings.ToLower(r.AuthUser.Username) {
		if !r.AuthUser.IsAdmin {
			Respond(w, r, http.StatusForbidden, "You don't have access to that user's account.", []interface{}{})
			return
		}
		id, err := r.GetUserID(username)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
			return
		}
		user, err = r.GetUser(id)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
			return
		}
	}
	resp, err := r.ResetSecret(user)
	if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	Respond(w, r, http.StatusOK, "Successfully reset secret", []interface{}{resp})
	return
}

func verifyEmail(w http.ResponseWriter, r *twocloud.RequestBundle) {
	var req verifyEmailRequest
	user := r.AuthUser
	username := r.Request.URL.Query().Get(":username")
	if strings.ToLower(username) != strings.ToLower(r.AuthUser.Username) {
		if !r.AuthUser.IsAdmin {
			Respond(w, r, http.StatusForbidden, "You don't have access to that user's account.", []interface{}{})
			return
		}
		id, err := r.GetUserID(username)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
			return
		}
		user, err = r.GetUser(id)
		if err != nil {
			r.Log.Error(err.Error())
			Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
			return
		}
	}
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
	if req.Code == "" {
		Respond(w, r, http.StatusBadRequest, "Code must be set.", []interface{}{})
		return
	}
	err = r.VerifyEmail(user, req.Code)
	if err == twocloud.InvalidConfirmationCodeError {
		Respond(w, r, http.StatusBadRequest, "Invalid confirmation code.", []interface{}{})
		return
	} else if err != nil {
		r.Log.Error(err.Error())
		Respond(w, r, http.StatusInternalServerError, "Internal server error.", []interface{}{})
		return
	}
	user.EmailUnconfirmed = false
	Respond(w, r, http.StatusOK, "Successfully verified email address", []interface{}{user})
	return
}

func auditUser(w http.ResponseWriter, r *twocloud.RequestBundle) {
}
