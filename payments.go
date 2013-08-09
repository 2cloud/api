package main

import (
	"get.2cloud.org/twocloud"
	"net/http"
	"strconv"
	"strings"
)

type payment struct {
	RemoteID          *string      `json:"remote_id,omitempty"`
	Amount            *int         `json:"amount,omitempty"`
	Message           *string      `json:"message,omitempty"`
	UserID            *twocloud.ID `json:"user_id,omitempty"`
	FundingSourceID   *twocloud.ID `json:"funding_source_id,omitempty"`
	FundingSourceType *string      `json:"funding_source_provider,omitempty"`
	Anonymous         *bool        `json:"anonymous,omitempty"`
	Campaign          *twocloud.ID `json:"campaign,omitempty"`
	Status            string       `json:"status,omitempty"`
	Error             string       `json:"error,omitempty"`
}

func getPayments(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	var after, before uint64
	var count int
	var status string
	var campaign, funding_source *twocloud.ID
	var user twocloud.User
	statuses := []string{}
	var err error
	afterstr := r.URL.Query().Get("after")
	beforestr := r.URL.Query().Get("before")
	countstr := r.URL.Query().Get("count")
	status = r.URL.Query().Get("status")
	userstr := r.URL.Query().Get(":username")
	campaignstr := r.URL.Query().Get(":campaign")
	fsstr := r.URL.Query().Get(":funding_source")
	if userstr != "" {
		user, err = b.getUser(userstr)
		if err == UnauthorisedAccessAttempt {
			Respond(w, http.StatusUnauthorized, "You don't have access to that payment.", []interface{}{AccessDenied("")})
			return
		}
		if err == twocloud.UserNotFoundError {
			Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("username")})
			return
		}
		if err != nil {
			b.Persister.Log.Error(err.Error())
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
			return
		}
	}
	if campaignstr != "" {
		campaignIDint, err := strconv.ParseUint(campaignstr, 10, 64)
		if err != nil {
			Respond(w, http.StatusBadRequest, "Invalid Campaign ID", []interface{}{InvalidFormat("campaign")})
			return
		}
		campaignID := twocloud.ID(campaignIDint)
		campaign = &campaignID
	}
	if fsstr != "" {
		fsIDint, err := strconv.ParseUint(fsstr, 10, 64)
		if err != nil {
			Respond(w, http.StatusBadRequest, "Invalid funding source ID", []interface{}{InvalidFormat("funding_source")})
			return
		}
		fsID := twocloud.ID(fsIDint)
		funding_source = &fsID
	}
	if status != "" {
		if b.AuthUser == nil || !b.AuthUser.IsAdmin {
			if status == twocloud.PAYMENT_STATUS_SUCCESS || status == twocloud.PAYMENT_STATUS_PENDING {
				statuses = append(statuses, status)
			} else {
				Respond(w, http.StatusUnauthorized, "You don't have access to payments with that status.", []interface{}{AccessDenied("status")})
				return
			}
		} else {
			statuses = append(statuses, twocloud.PAYMENT_STATUS_SUCCESS, twocloud.PAYMENT_STATUS_PENDING)
		}
	}
	if afterstr != "" {
		after, err = strconv.ParseUint(afterstr, 10, 64)
		if err != nil {
			Respond(w, http.StatusBadRequest, "Invalid after ID.", []interface{}{InvalidFormat("after")})
			return
		}
	}
	if beforestr != "" {
		before, err = strconv.ParseUint(beforestr, 10, 64)
		if err != nil {
			Respond(w, http.StatusBadRequest, "Invalid before ID.", []interface{}{InvalidFormat("before")})
			return
		}
	}
	count = 20
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
	var payments []twocloud.Payment
	payments, err = b.Persister.GetPayments(twocloud.ID(before), twocloud.ID(after), count, statuses, &user.ID, campaign, funding_source)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	if !b.AuthUser.IsAdmin {
		for index, _ := range payments {
			if payments[index].UserID != b.AuthUser.ID {
				if payments[index].Anonymous {
					payments[index].UserID = twocloud.ID(0)
				}
				payments[index].RemoteID = ""
				payments[index].FundingSourceID = twocloud.ID(0)
				payments[index].Error = ""
			}
		}
	}
	Respond(w, http.StatusOK, "Successfully retrieved a list of payments", []interface{}{payments})
}

func getPayment(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	idstr := r.URL.Query().Get(":id")
	if idstr == "" {
		Respond(w, http.StatusBadRequest, "ID missing", []interface{}{MissingParam("id")})
		return
	}
	id, err := strconv.ParseUint(idstr, 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid ID", []interface{}{InvalidFormat("id")})
		return
	}
	var payment twocloud.Payment
	payment, err = b.Persister.GetPayment(twocloud.ID(id))
	if err != nil {
		if err == twocloud.PaymentNotFoundError {
			Respond(w, http.StatusNotFound, "No such payment", []interface{}{NotFound("id")})
			return
		}
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	if !b.AuthUser.IsAdmin && b.AuthUser.ID != payment.UserID {
		if payment.Status != twocloud.PAYMENT_STATUS_PENDING && payment.Status != twocloud.PAYMENT_STATUS_SUCCESS {
			Respond(w, http.StatusNotFound, "No such payment", []interface{}{NotFound("id")})
			return
		}
		if payment.Anonymous {
			payment.UserID = twocloud.ID(0)
		}
		payment.RemoteID = ""
		payment.FundingSourceID = twocloud.ID(0)
		payment.Error = ""
	}
	Respond(w, http.StatusOK, "Successfully retrieved a list of payments.", []interface{}{payment})
}

func newPayment(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	request, err := getRequest(r)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		if isUnmarshalError(err) {
			Respond(w, http.StatusBadRequest, "Error decoding request.", []interface{}{BadRequestFormat("")})
		} else {
			Respond(w, http.StatusBadRequest, "Internal server error.", []interface{}{ActOfGod("")})
		}
		return
	}
	if request.Payment == nil {
		Respond(w, http.StatusBadRequest, "Must supply payment information", []interface{}{MissingParam("payment")})
		return
	}
	if request.Payment.Amount == nil {
		Respond(w, http.StatusBadRequest, "Missing payment amount.", []interface{}{MissingParam("payment.amount")})
		return
	}
	if *request.Payment.Amount <= 0 {
		Respond(w, http.StatusBadRequest, "Invalid payment amount.", []interface{}{TooShort("payment.amount")})
		return
	}
	if request.Payment.UserID == nil {
		Respond(w, http.StatusBadRequest, "Invalid user ID.", []interface{}{MissingParam("payment.user_id")})
		return
	}
	if *request.Payment.UserID != b.AuthUser.ID && !b.AuthUser.IsAdmin {
		Respond(w, http.StatusUnauthorized, "You cannot create payments for that user.", []interface{}{AccessDenied("payment.user_id")})
		return
	}
	if request.Payment.FundingSourceID == nil {
		Respond(w, http.StatusBadRequest, "Invalid funding source ID.", []interface{}{MissingParam("payment.funding_source_id")})
		return
	}
	if request.Payment.FundingSourceType == nil {
		Respond(w, http.StatusBadRequest, "Missing funding source type.", []interface{}{MissingParam("payment.funding_source_provider")})
		return
	}
	provider := strings.ToLower(*request.Payment.FundingSourceType)
	if !twocloud.IsValidProvider(provider) {
		Respond(w, http.StatusBadRequest, "Not a valid funding source provider.", []interface{}{InvalidValue("payment.funding_source_provider")})
		return
	}
	if request.Payment.Campaign == nil {
		Respond(w, http.StatusBadRequest, "Invalid campaign ID.", []interface{}{MissingParam("payment.campaign")})
		return
	}
	switch provider {
	case "stripe":
		source, err := b.Persister.GetStripeSource(*request.Payment.FundingSourceID)
		if err != nil {
			if err == twocloud.FundingSourceNotFoundError {
				Respond(w, http.StatusNotFound, "Funding source not found.", []interface{}{NotFound("payment.funding_source_id")})
				return
			}
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
			return
		}
		if source.UserID != *request.Payment.UserID {
			Respond(w, http.StatusBadRequest, "Funding source does not belong to specified user.", []interface{}{WrongOwner("payment.funding_source_id")})
			return
		}
	}
	payment, err := b.Persister.AddPayment(*request.Payment.Amount, *request.Payment.Message, *request.Payment.UserID, *request.Payment.FundingSourceID, *request.Payment.Campaign, *request.Payment.Anonymous)
	if err != nil {
		if err == twocloud.PaymentNegativeAmountError {
			Respond(w, http.StatusBadRequest, "Invalid payment amount.", []interface{}{TooShort("payment.amount")})
			return
		}
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusCreated, "Successfully created a payment", []interface{}{payment})
}

func updatePayment(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	request, err := getRequest(r)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		if isUnmarshalError(err) {
			Respond(w, http.StatusBadRequest, "Error decoding request.", []interface{}{BadRequestFormat("")})
		} else {
			Respond(w, http.StatusBadRequest, "Internal server error.", []interface{}{ActOfGod("")})
		}
		return
	}
	if request.Payment == nil {
		Respond(w, http.StatusBadRequest, "Must supply payment information", []interface{}{MissingParam("payment")})
		return
	}
	if request.Payment.Amount != nil && *request.Payment.Amount <= 0 {
		Respond(w, http.StatusBadRequest, "Invalid payment amount.", []interface{}{TooShort("payment.amount")})
		return
	}
	if request.Payment.UserID != nil && *request.Payment.UserID != b.AuthUser.ID && !b.AuthUser.IsAdmin {
		Respond(w, http.StatusUnauthorized, "You cannot update payments for that user.", []interface{}{AccessDenied("payment.user_id")})
		return
	}
	if request.Payment.FundingSourceID != nil {
		if request.Payment.FundingSourceType == nil {
			Respond(w, http.StatusBadRequest, "You must specify the funding source provider if you specify a funding source ID.", []interface{}{MissingParam("payment.funding_source_provider")})
			return
		}
		provider := strings.ToLower(*request.Payment.FundingSourceType)
		if !twocloud.IsValidProvider(provider) {
			Respond(w, http.StatusBadRequest, "Not a valid funding source provider.", []interface{}{InvalidValue("payment.funding_source_provider")})
			return
		}
		switch *request.Payment.FundingSourceType {
		case "stripe":
			source, err := b.Persister.GetStripeSource(*request.Payment.FundingSourceID)
			if err != nil {
				if err == twocloud.FundingSourceNotFoundError {
					Respond(w, http.StatusNotFound, "Funding source not found.", []interface{}{NotFound("payment.funding_source_id")})
					return
				}
				Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
				return
			}
			if source.UserID != *request.Payment.UserID {
				Respond(w, http.StatusBadRequest, "Funding source does not belong to specified user.", []interface{}{WrongOwner("payment.funding_source_id")})
				return
			}
		}
	}
	idstr := r.URL.Query().Get(":id")
	if idstr == "" {
		Respond(w, http.StatusBadRequest, "ID missing", []interface{}{MissingParam("id")})
		return
	}
	id, err := strconv.ParseUint(idstr, 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid ID", []interface{}{InvalidFormat("id")})
		return
	}
	var payment twocloud.Payment
	payment, err = b.Persister.GetPayment(twocloud.ID(id))
	if err != nil {
		if err == twocloud.PaymentNotFoundError {
			Respond(w, http.StatusNotFound, "No such payment", []interface{}{NotFound("id")})
			return
		}
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	if !b.AuthUser.IsAdmin && payment.UserID != b.AuthUser.ID {
		Respond(w, http.StatusUnauthorized, "You don't have access to that user's payments.", []interface{}{AccessDenied("payment.user_id")})
		return
	}
	if !b.AuthUser.IsAdmin && payment.Status != twocloud.PAYMENT_STATUS_PENDING && payment.Status != twocloud.PAYMENT_STATUS_RETRY {
		Respond(w, http.StatusUnauthorized, "You aren't authorized to update non-pending payments.", []interface{}{AccessDenied("payment.status")})
		return
	}
	err = b.Persister.UpdatePayment(&payment, request.Payment.Amount, request.Payment.Message, request.Payment.UserID, request.Payment.FundingSourceID, request.Payment.Campaign, request.Payment.Anonymous)
	if err != nil {
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully updated the payment.", []interface{}{payment})
}

func updatePaymentStatus(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	if !b.AuthUser.IsAdmin {
		Respond(w, http.StatusBadRequest, "You can't update payment statuses.", []interface{}{AccessDenied("")})
		return
	}
	request, err := getRequest(r)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		if isUnmarshalError(err) {
			Respond(w, http.StatusBadRequest, "Error decoding request.", []interface{}{BadRequestFormat("")})
		} else {
			Respond(w, http.StatusBadRequest, "Internal server error.", []interface{}{ActOfGod("")})
		}
		return
	}
	if request.Payment == nil {
		Respond(w, http.StatusBadRequest, "Must supply payment information", []interface{}{MissingParam("payment")})
		return
	}
	if request.Payment.Status == "" {
		Respond(w, http.StatusBadRequest, "Must supply payment status.", []interface{}{MissingParam("payment.status")})
		return
	}
	request.Payment.Status = strings.ToLower(request.Payment.Status)
	if !twocloud.IsValidPaymentStatus(request.Payment.Status) {
		Respond(w, http.StatusBadRequest, "Invalid payment status.", []interface{}{InvalidValue("payment.status")})
		return
	}
	idstr := r.URL.Query().Get(":id")
	if idstr == "" {
		Respond(w, http.StatusBadRequest, "ID missing", []interface{}{MissingParam("id")})
		return
	}
	id, err := strconv.ParseUint(idstr, 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid ID", []interface{}{InvalidFormat("id")})
		return
	}
	var payment twocloud.Payment
	payment, err = b.Persister.GetPayment(twocloud.ID(id))
	if err != nil {
		if err == twocloud.PaymentNotFoundError {
			Respond(w, http.StatusNotFound, "No such payment", []interface{}{NotFound("id")})
			return
		}
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	err = b.Persister.UpdatePaymentStatus(&payment, request.Payment.Status, request.Payment.Error)
	if err != nil {
		if err == twocloud.PaymentInvalidStatusError {
			Respond(w, http.StatusBadRequest, "Invalid payment status.", []interface{}{InvalidValue("payment.status")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully updated the payment.", []interface{}{payment})
}

func deletePayment(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	idstr := r.URL.Query().Get(":id")
	if idstr == "" {
		Respond(w, http.StatusBadRequest, "ID missing", []interface{}{MissingParam("id")})
		return
	}
	id, err := strconv.ParseUint(idstr, 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid ID", []interface{}{InvalidFormat("id")})
		return
	}
	var payment twocloud.Payment
	payment, err = b.Persister.GetPayment(twocloud.ID(id))
	if err != nil {
		if err == twocloud.PaymentNotFoundError {
			Respond(w, http.StatusNotFound, "No such payment", []interface{}{NotFound("id")})
			return
		}
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	if !b.AuthUser.IsAdmin && payment.UserID != b.AuthUser.ID {
		Respond(w, http.StatusUnauthorized, "You don't have access to that user's payments.", []interface{}{AccessDenied("payment.user_id")})
		return
	}
	if !b.AuthUser.IsAdmin && payment.Status != twocloud.PAYMENT_STATUS_PENDING && payment.Status != twocloud.PAYMENT_STATUS_RETRY {
		Respond(w, http.StatusUnauthorized, "You aren't authorized to delete non-pending payments.", []interface{}{AccessDenied("payment.status")})
		return
	}
	err = b.Persister.DeletePayment(payment)
	if err != nil {
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully deleted the payment.", []interface{}{payment})
}
