package main

import (
	"get.2cloud.org/twocloud"
	"net/http"
	"strconv"
	"time"
)

type campaign struct {
	Title       *string
	Description *string
	Goal        *int
	Auxilliary  *bool
	Starts      *time.Time
	Ends        *time.Time
}

func getCampaigns(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	var after, before uint64
	var count int
	var current, aux *bool
	var err error
	afterstr := r.URL.Query().Get("after")
	beforestr := r.URL.Query().Get("before")
	countstr := r.URL.Query().Get("count")
	currentstr := r.URL.Query().Get("current")
	auxstr := r.URL.Query().Get("auxilliary")
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
	if currentstr != "" {
		isCurrent := currentstr == "true"
		current = &isCurrent
	}
	if auxstr != "" {
		isAux := auxstr == "true"
		aux = &isAux
	}
	var campaigns []twocloud.Campaign
	campaigns, err = b.Persister.GetCampaigns(current, aux, twocloud.ID(before), twocloud.ID(after), count, b.AuthUser.IsAdmin)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully retrieved a list of campaigns", []interface{}{campaigns})
	return
}

func getCampaign(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	var id uint64
	var err error
	idstr := r.URL.Query().Get("id")
	if idstr == "" {
		Respond(w, http.StatusBadRequest, "Missing ID.", []interface{}{MissingParam("id")})
		return
	}
	id, err = strconv.ParseUint(idstr, 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid ID format.", []interface{}{InvalidFormat("id")})
		return
	}
	campaign, err := b.Persister.GetCampaign(twocloud.ID(id), b.AuthUser.IsAdmin)
	if err != nil {
		if err == twocloud.CampaignNotFoundError {
			Respond(w, http.StatusNotFound, "Campaign not found.", []interface{}{NotFound("id")})
			return
		}
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully retrieved campaign", []interface{}{campaign})
	return
}

func newCampaign(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	if !b.AuthUser.IsAdmin {
		Respond(w, http.StatusForbidden, "You are not authorised to create campaigns.", []interface{}{AccessDenied("")})
		return
	}
	request, err := getRequest(r)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		if isUnmarshalError(err) {
			Respond(w, http.StatusBadRequest, "Error decoding request.", []interface{}{BadRequestFormat("")})
		} else {
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		}
		return
	}
	if request.Campaign == nil {
		Respond(w, http.StatusBadRequest, "Must supply campaign.", []interface{}{MissingParam("campaign")})
		return
	}
	if request.Campaign.Title == nil {
		Respond(w, http.StatusBadRequest, "Title must be specified.", []interface{}{MissingParam("cmapaign.title")})
		return
	}
	if request.Campaign.Description == nil {
		Respond(w, http.StatusBadRequest, "Description must be specified.", []interface{}{MissingParam("campaign.description")})
		return
	}
	if request.Campaign.Goal == nil {
		Respond(w, http.StatusBadRequest, "Goal must be specified.", []interface{}{MissingParam("campaign.goal")})
		return
	}
	if request.Campaign.Starts == nil {
		request.Campaign.Starts = &time.Time{}
	}
	if request.Campaign.Ends == nil {
		request.Campaign.Ends = &time.Time{}
	}
	if request.Campaign.Auxilliary == nil {
		Respond(w, http.StatusBadRequest, "Auxilliary must be specified.", []interface{}{MissingParam("campaign.auxilliary")})
		return
	}
	campaign, err := b.Persister.AddCampaign(*request.Campaign.Title, *request.Campaign.Description, *request.Campaign.Goal, *request.Campaign.Auxilliary, *request.Campaign.Starts, *request.Campaign.Ends)
	if err != nil {
		if err == twocloud.CampaignEmptyTitleError {
			Respond(w, http.StatusBadRequest, "Title must be specified.", []interface{}{MissingParam("campaign.title")})
			return
		}
		if err == twocloud.CampaignEmptyDescriptionError {
			Respond(w, http.StatusBadRequest, "Description must be specified.", []interface{}{MissingParam("campaign.description")})
			return
		}
		if err == twocloud.CampaignNegativeGoalError {
			Respond(w, http.StatusBadRequest, "Goal must be 0 or higher.", []interface{}{TooShort("campaign.goal")})
			return
		}
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully created campaign", []interface{}{campaign})
	return
}

func updateCampaign(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	if !b.AuthUser.IsAdmin {
		Respond(w, http.StatusForbidden, "You are not authorised to edit campaigns.", []interface{}{AccessDenied("")})
		return
	}
	request, err := getRequest(r)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		if isUnmarshalError(err) {
			Respond(w, http.StatusBadRequest, "Error decoding request.", []interface{}{BadRequestFormat("")})
		} else {
			Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		}
		return
	}
	if request.Campaign == nil {
		Respond(w, http.StatusBadRequest, "Must supply campaign.", []interface{}{MissingParam("campaign")})
		return
	}
	var id uint64
	idstr := r.URL.Query().Get("id")
	if idstr == "" {
		Respond(w, http.StatusBadRequest, "Missing ID.", []interface{}{MissingParam("id")})
		return
	}
	id, err = strconv.ParseUint(idstr, 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid ID format.", []interface{}{InvalidFormat("id")})
		return
	}
	campaign, err := b.Persister.GetCampaign(twocloud.ID(id), b.AuthUser.IsAdmin)
	if err != nil {
		if err == twocloud.CampaignNotFoundError {
			Respond(w, http.StatusNotFound, "Campaign not found.", []interface{}{NotFound("id")})
			return
		}
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	err = b.Persister.UpdateCampaign(&campaign, request.Campaign.Title, request.Campaign.Description, request.Campaign.Goal, request.Campaign.Auxilliary, request.Campaign.Starts, request.Campaign.Ends)
	if err != nil {
		if err == twocloud.CampaignNegativeGoalError {
			Respond(w, http.StatusBadRequest, "Goal must be 0 or higher.", []interface{}{TooShort("campaign.goal")})
			return
		}
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully updated campaign", []interface{}{campaign})
	return
}

func deleteCampaign(w http.ResponseWriter, r *http.Request, b *RequestBundle) {
	var id uint64
	var err error
	idstr := r.URL.Query().Get("id")
	if idstr == "" {
		Respond(w, http.StatusBadRequest, "Missing ID.", []interface{}{MissingParam("id")})
		return
	}
	id, err = strconv.ParseUint(idstr, 10, 64)
	if err != nil {
		Respond(w, http.StatusBadRequest, "Invalid ID format.", []interface{}{InvalidFormat("id")})
		return
	}
	campaign, err := b.Persister.GetCampaign(twocloud.ID(id), b.AuthUser.IsAdmin)
	if err != nil {
		if err == twocloud.CampaignNotFoundError {
			Respond(w, http.StatusNotFound, "Campaign not found.", []interface{}{NotFound("id")})
			return
		}
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	err = b.Persister.DeleteCampaign(campaign)
	if err != nil {
		b.Persister.Log.Error(err.Error())
		Respond(w, http.StatusInternalServerError, "Internal server error", []interface{}{ActOfGod("")})
		return
	}
	Respond(w, http.StatusOK, "Successfully deleted campaign", []interface{}{campaign})
	return
}
