package main

import (
	"encoding/json"
	"get.2cloud.org/twocloud"
	"io/ioutil"
	"net/http"
)

type RequestData struct {
	Account           *account                 `json:"account,omitempty"`
	Tokens            *tokens                  `json:"tokens,omitempty"`
	Device            *device                  `json:"device,omitempty"`
	Links             []link                   `json:"links,omitempty"`
	Link              *link                    `json:"link,omitempty"`
	Notifications     []notification           `json:"notifications,omitempty"`
	Notification      *notification            `json:"notification,omitempty"`
	BroadcastFilter   *broadcastFilter         `json:"broadcast_filter,omitempty"`
	Subscription      *subscription            `json:"subscription,omitempty"`
	User              *user                    `json:"user,omitempty"`
	EmailVerification *emailVerification       `json:"email_verification,omitempty"`
	FundingSources    *twocloud.FundingSources `json:"funding_sources,omitempty"`
}

func getRequest(r *http.Request) (RequestData, error) {
	var req RequestData
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return RequestData{}, err
	}
	err = json.Unmarshal(body, &req)
	if err != nil {
		return RequestData{}, err
	}
	return req, nil
}

func isUnmarshalError(err error) bool {
	if _, ok := err.(*json.InvalidUTF8Error); ok {
		return true
	}
	if _, ok := err.(*json.InvalidUnmarshalError); ok {
		return true
	}
	if _, ok := err.(*json.SyntaxError); ok {
		return true
	}
	if _, ok := err.(*json.UnmarshalFieldError); ok {
		return true
	}
	if _, ok := err.(*json.UnmarshalTypeError); ok {
		return true
	}
	if _, ok := err.(*json.UnsupportedTypeError); ok {
		return true
	}
	if _, ok := err.(*json.UnsupportedValueError); ok {
		return true
	}
	return false
}
