package main

import (
	"get.2cloud.org/twocloud"
	"net/http"
	"strconv"
	"time"
)

func getPayments(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	var after, before uint64
	var count int
	var status string
	var campaign, user, funding_source *twocloud.ID
	statuses := []string{}
	var err error
	afterstr := r.URL.Query().Get("after")
	beforestr := r.URL.Query().Get("before")
	countstr := r.URL.Query().Get("count")
	status = r.UrL.Query().Get("status")
	userstr := r.URL.Query().Get(":username")
	campaignstr := r.URL.Query().Get(":campaign")
	fsstr := r.URL.Query().Get(":funding_source")
	if userstr != "" {
		user, err = b.getUser(userstr)
		if err == UnauthorisedAccessAttempt {
			// TODO: Return an error
		}
		if err == twocloud.UserNotFoundError {
			// TODO: Return an error
		}
		if err != nil {
			// TODO: Return an error
			// TODO: Log error
		}
	}
	if campaignstr != "" {
		campaignID, err := strconv.ParseUint(campaignstr, 10, 64)
		if err != nil {
			Respond(w, http.StatusBadRequest, "Invalid Campaign ID", []interface{}{InvalidFormat("campaign")})
			return
		}
		campaign = &twocloud.ID(campaignID)
	}
	if fsstr != "" {
		fsID, err := strconv.ParseUint(fsstr, 10, 64)
		if err != nil {
			Respond(w, http.StatusBadRequest, "Invalid funding source ID", []interface{}{InvalidFormat("funding_source")})
			return
		}
		funding_source = &twocloud.ID(fsID)
	}
	if status != "" {
		if b.AuthUser == nil || !b.AuthUser.IsAdmin {
			if status == twocloud.PAYMENT_STATUS_SUCCESS || status == twocloud.PAYMENT_STATUS_PENDING {
				statuses = append(statuses, status)
			} else {
				// TODO: Return error
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
	payments, err = b.Persister.GetPayments(before, after, count, statuses, user.ID, campaign, funding_source)
	if err != nil {
		// TODO: log error
		// TODO: return error
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
	payment, err = b.Persister.GetPayment(id)
	if err != nil {
		if err == twocloud.PaymentNotFoundError {
			Respond(w, http.StatusNotFound, "No such payment", []interface{}{NotFound("id")})
			return
		}
		// TODO: log error
		// TODO: Return error
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
	if request.Payment.Amount <= 0 {
		// TODO: return error
	}
	if request.Payment.UserID == twocloud.ID(0) {
		// TODO: return error
	}
	if request.Payment.UserID != b.AuthUser.ID && !b.AuthUser.IsAdmin {
		// TODO: return error
	}
	if request.Payment.FundingSourceID == twocloud.ID(0) {
		// TODO: return error
	}
	if request.Payment.Campaign == twocloud.ID(0) {
		// TODO: return error
	}
	// TODO: retrieve funding source
	// TODO: ensure funding source belongs to request.Payment.UserID
	payment, err := b.Persister.AddPayment(request.Payment.Amount, request.Payment.Message, request.Payment.UserID, request.Payment.FundingSourceID, request.Payment.Campaign, request.Payment.Anonymous)
	if err != nil {
		if err == twocloud.PaymentNegativeAmountError {
			// TODO: return error
		}
		// TODO: log error
		// TODO: return error
	}
	Respond(w, http.StatusCreated, "Successfully created a payment", []interface{}{payment}
}

func chargePayment(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
}

func updatePayment(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
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
	payment, err = b.Persister.GetPayment(id)
	if err != nil {
		if err == twocloud.PaymentNotFoundError {
			Respond(w, http.StatusNotFound, "No such payment", []interface{}{NotFound("id")})
			return
		}
		// TODO: log error
		// TODO: Return error
	}
	if !b.AuthUser.IsAdmin && payment.UserID != b.AuthUser.ID {
		// TODO: return an error
	}
	if !b.AuthUser.IsAdmin && payment.Status != twocloud.PAYMENT_STATUS_PENDING && payment.Status != twocloud.PAYMENT_STATUS_RETRY {
		// TODO: return error
	}
	err = b.Persister.DeletePayment(payment)
	if err != nil {
		// TODO: log error
		// TODO: return error
	}
	Respond(w, http.StatusOK, "Successfully deleted the payment.", []interface{}{payment})
}
