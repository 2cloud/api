package main

import (
	"get.2cloud.org/twocloud"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type subscription struct {
	Amount            *uint64      `json:"amount,omitempty"`
	Period            *string      `json:"period,omitempty"`
	Renews            *time.Time   `json:"renews,omitempty"`
	NotifyOnRenewal   *bool        `json:"notify_on_renewal,omitempty"`
	Campaign          *twocloud.ID `json:"campaign,omitempty"`
	FundingSourceID   *twocloud.ID `json:"funding_id,omitempty"`
	FundingSourceType *string      `json:"funding_source,omitempty"`
	UserID            *twocloud.ID `json:"user_id,omitempty"`
}

func getSubscriptions(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	username := r.URL.Query().Get(":username")
	if !b.AuthUser.IsAdmin && (username == "" || strings.ToLower(username) != strings.ToLower(b.AuthUser.Username)) {
		Respond(w, http.StatusBadRequest, "You don't have permission to list those subscriptions.", []interface{}{AccessDenied("")})
		return
	}
	var after, before twocloud.ID
	var err error
	afterStr := r.URL.Query().Get("after")
	after, err = twocloud.IDFromString(afterStr)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid after ID. Needs to be a valid subscription ID.", []interface{}{InvalidFormat("after")})
		return
	}
	beforeStr := r.URL.Query().Get("before")
	before, err = twocloud.IDFromString(beforeStr)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid before ID. Needs to be a valid subscription ID.", []interface{}{InvalidFormat("before")})
		return
	}
	status := r.URL.Query().Get("status")
	count := 20
	countStr := r.URL.Query().Get("count")
	if countStr != "" {
		newcount, err := strconv.Atoi(countStr)
		if err != nil {
			Respond(w, http.StatusBadRequest, "Invalid count.", []interface{}{InvalidFormat("count")})
			return
		}
		if newcount > 0 && newcount <= 100 {
			count = newcount
		} else if newcount <= 0 {
			Respond(w, http.StatusBadRequest, "Count must be greater than 0.", []interface{}{TooShort("count")})
			return
		} else if newcount > 100 {
			Respond(w, http.StatusBadRequest, "Count must be less than 100.", []interface{}{TooLong("count")})
			return
		}
	}
	var subscriptions []twocloud.Subscription
	if username != "" {
		user, err := b.getUser(username)
		if err != nil {
			if err == twocloud.UserNotFoundError {
				Respond(w, http.StatusNotFound, "User not found.", []interface{}{NotFound("username")})
				return
			}
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
			return
		}
		subscriptions, err = b.Persister.GetSubscriptionsByUser(user.ID, after, before, count)
	} else {
		subscriptions, err = b.Persister.GetSubscriptionsByExpiration(status, after, before, count)
	}
	if err != nil {
		if err == twocloud.InvalidStatusError {
			Respond(w, http.StatusBadRequest, "Invalid status passed.", []interface{}{InvalidValue("status")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully retrieved list of subscriptions.", []interface{}{subscriptions})
}

func getSubscription(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	idStr := r.URL.Query().Get(":id")
	if idStr == "" {
		Respond(w, http.StatusBadRequest, "Missing id.", []interface{}{MissingParam("id")})
		return
	}
	id, err := twocloud.IDFromString(idStr)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid ID format.", []interface{}{InvalidFormat("id")})
		return
	}
	subscription, err := b.Persister.GetSubscription(id)
	if err != nil {
		if err == twocloud.SubscriptionNotFoundError {
			Respond(w, http.StatusNotFound, "Subscription not found.", []interface{}{NotFound("id")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	if subscription.UserID != b.AuthUser.ID && !b.AuthUser.IsAdmin {
		Respond(w, http.StatusUnauthorized, "You don't have access to that subscription.", []interface{}{AccessDenied("id")})
		return
	}
	Respond(w, http.StatusOK, "Susccessfully retrieved subscription.", []interface{}{subscription})
	return
}

func createSubscription(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	request, err := getRequest(r)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		if isUnmarshalError(err) {
			Respond(w, http.StatusBadRequest, "Error decoding request.", []interface{}{BadRequestFormat("")})
			return
		} else {
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
			return
		}
	}
	if request.Subscription == nil {
		Respond(w, http.StatusBadRequest, "Subscription must be included in request.", []interface{}{MissingParam("subscription")})
		return
	}
	var amount uint64
	var period, funding_src string
	var renews time.Time
	var notify bool
	var campaign_id, user_id, funding_id twocloud.ID
	if request.Subscription.Amount == nil {
		Respond(w, http.StatusBadRequest, "Missing amount.", []interface{}{MissingParam("subscription.amount")})
		return
	}
	amount = *request.Subscription.Amount
	if request.Subscription.Period == nil {
		Respond(w, http.StatusBadRequest, "Missing period.", []interface{}{MissingParam("subscription.period")})
		return
	}
	period = *request.Subscription.Period
	if request.Subscription.Renews != nil {
		renews = *request.Subscription.Renews
	}
	if request.Subscription.NotifyOnRenewal == nil {
		notify = true
	} else {
		notify = *request.Subscription.NotifyOnRenewal
	}
	if request.Subscription.Campaign != nil {
		campaign_id = *request.Subscription.Campaign
		if !campaign_id.IsZero() {
			campaign, err := b.Persister.GetCampaign(campaign_id, b.AuthUser.IsAdmin)
			if err != nil {
				if err == twocloud.CampaignNotFoundError {
					Respond(w, http.StatusNotFound, "Campaign not found.", []interface{}{NotFound("subscription.campaign_id")})
					return
				}
				Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
				return
			}
			if campaign.Ends.Before(time.Now()) && !campaign.Ends.IsZero() {
				Respond(w, http.StatusBadRequest, "That campaign has ended.", []interface{}{InvalidValue("subscription.campaign_id")})
				return
			}
		}
	}
	if request.Subscription.UserID == nil {
		user_id = b.AuthUser.ID
	} else {
		if !b.AuthUser.IsAdmin && b.AuthUser.ID != *request.Subscription.UserID {
			Respond(w, http.StatusUnauthorized, "You don't have permission to create a subscription for that user.", []interface{}{AccessDenied("subscription.user_id")})
			return
		}
		user_id = *request.Subscription.UserID
	}
	if request.Subscription.FundingSourceID == nil {
		Respond(w, http.StatusBadRequest, "Missing funding_id.", []interface{}{MissingParam("subscription.funding_id")})
		return
	}
	funding_id = *request.Subscription.FundingSourceID
	if request.Subscription.FundingSourceType == nil {
		Respond(w, http.StatusBadRequest, "Missing funding_source.", []interface{}{MissingParam("subscription.funding_source")})
		return
	}
	funding_src = *request.Subscription.FundingSourceType
	if !twocloud.IsValidProvider(funding_src) {
		Respond(w, http.StatusBadRequest, "Invalid funding source provider.", []interface{}{InvalidValue("subscription.funding_source")})
		return
	}
	switch strings.ToLower(funding_src) {
	case "stripe":
		stripe_src, err := b.Persister.GetStripeSource(funding_id)
		if err != nil {
			if err == twocloud.FundingSourceNotFoundError {
				Respond(w, http.StatusNotFound, "Funding source not found.", []interface{}{NotFound("subscription.funding_id")})
				return
			}
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
			return
		}
		if stripe_src.UserID != user_id {
			Respond(w, http.StatusBadRequest, "Funding source does not belong to the specified user.", []interface{}{WrongOwner("subscription.funding_id")})
			return
		}
	default:
		Respond(w, http.StatusBadRequest, "Invalid funding source provider.", []interface{}{InvalidValue("subscription.funding_source")})
		return
	}
	subscription, err := b.Persister.CreateSubscription(amount, period, renews, notify, campaign_id, user_id, funding_id, funding_src)
	if err != nil {
		if err == twocloud.InvalidPeriodError {
			Respond(w, http.StatusBadRequest, "Invalid period.", []interface{}{InvalidValue("subscription.period")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusCreated, "Successfully created subscription.", []interface{}{subscription})
	return
}

func updateSubscription(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	idStr := r.URL.Query().Get(":id")
	if idStr == "" {
		Respond(w, http.StatusBadRequest, "Missing subscription ID.", []interface{}{MissingParam("id")})
		return
	}
	id, err := twocloud.IDFromString(idStr)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid subscription ID.", []interface{}{InvalidFormat("id")})
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
	if request.Subscription == nil {
		Respond(w, http.StatusBadRequest, "Subscription must be included in request.", []interface{}{MissingParam("subscription")})
		return
	}
	subscription, err := b.Persister.GetSubscription(id)
	if err != nil {
		if err == twocloud.SubscriptionNotFoundError {
			Respond(w, http.StatusNotFound, "Subscription not found.", []interface{}{NotFound("id")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	if subscription.UserID != b.AuthUser.ID && !b.AuthUser.IsAdmin {
		Respond(w, http.StatusUnauthorized, "You don't have access to that subscription.", []interface{}{AccessDenied("")})
		return
	}
	if request.Subscription.UserID != nil && *request.Subscription.UserID != b.AuthUser.ID && !b.AuthUser.IsAdmin {
		Respond(w, http.StatusUnauthorized, "You don't have access to that user's subscriptions.", []interface{}{AccessDenied("subscription.user_id")})
		return
	}
	if request.Subscription.FundingSourceType != nil || request.Subscription.FundingSourceID != nil {
		funding_src := subscription.FundingSource
		if request.Subscription.FundingSourceType != nil {
			funding_src = *request.Subscription.FundingSourceType
		}
		funding_id := subscription.FundingID
		if request.Subscription.FundingSourceID != nil {
			funding_id = *request.Subscription.FundingSourceID
		}
		switch strings.ToLower(funding_src) {
		case "stripe":
			stripe_src, err := b.Persister.GetStripeSource(funding_id)
			if err != nil {
				if err == twocloud.FundingSourceNotFoundError {
					Respond(w, http.StatusNotFound, "Funding source not found.", []interface{}{NotFound("subscription.funding_id")})
					return
				}
				Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
				return
			}
			if (request.Subscription.UserID != nil && *request.Subscription.UserID != stripe_src.UserID) || (stripe_src.UserID != subscription.UserID) {
				Respond(w, http.StatusBadRequest, "That funding source doesn't belong to the user that owns that subscription.", []interface{}{WrongOwner("subscription.funding_id")})
				return
			}
		default:
			Respond(w, http.StatusBadRequest, "Invalid funding source provider.", []interface{}{InvalidValue("subscription.funding_source")})
			return
		}
	}
	if request.Subscription.Campaign != nil && !request.Subscription.Campaign.IsZero() {
		campaign, err := b.Persister.GetCampaign(*request.Subscription.Campaign, b.AuthUser.IsAdmin)
		if err != nil {
			if err == twocloud.CampaignNotFoundError {
				Respond(w, http.StatusNotFound, "Campaign not found.", []interface{}{NotFound("subscription.campaign_id")})
				return
			}
			Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
			return
		}
		if campaign.Ends.Before(time.Now()) && !campaign.Ends.IsZero() {
			Respond(w, http.StatusBadRequest, "That campaign has ended.", []interface{}{InvalidValue("subscription.campaign_id")})
			return
		}
	}
	err = b.Persister.UpdateSubscription(subscription, request.Subscription.Amount, request.Subscription.Period, request.Subscription.Renews, request.Subscription.NotifyOnRenewal, request.Subscription.Campaign, request.Subscription.UserID, request.Subscription.FundingSourceID, request.Subscription.FundingSourceType)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully updated the subscription", []interface{}{subscription})
	return
}

func cancelSubscription(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	var err error
	var id twocloud.ID
	var subscription *twocloud.Subscription
	idStr := r.URL.Query().Get(":id")
	if idStr == "" {
		Respond(w, http.StatusBadRequest, "Missing ID.", []interface{}{MissingParam("id")})
		return
	}
	id, err = twocloud.IDFromString(idStr)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid ID format.", []interface{}{InvalidFormat("id")})
		return
	}
	subscription, err = b.Persister.GetSubscription(id)
	if err != nil {
		if err == twocloud.SubscriptionNotFoundError {
			Respond(w, http.StatusNotFound, "Subscription not found.", []interface{}{NotFound("id")})
			return
		}
		Respond(w, http.StatusInternalServerError, "Internal server error.", []interface{}{ActOfGod("")})
		return
	}
	if subscription.UserID != b.AuthUser.ID && !b.AuthUser.IsAdmin {
		Respond(w, http.StatusUnauthorized, "You don't have access to that subscription.", []interface{}{AccessDenied("")})
		return
	}
	err = b.Persister.CancelSubscription(*subscription)
	if err != nil {
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully canceled the subscription", []interface{}{subscription})
	return
}
