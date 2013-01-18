package main

import (
	"encoding/json"
	"get.2cloud.org/twocloud"
	"net/http"
	"os"
	"sort"
	"strings"
)

type Response struct {
	Code          int                     `json:"code"`
	Message       string                  `json:"message"`
	Accounts      []twocloud.Account      `json:"accounts,omitempty"`
	Devices       []twocloud.Device       `json:"devices,omitempty"`
	Links         []twocloud.Link         `json:"links,omitempty"`
	Notifications []twocloud.Notification `json:"notifications,omitempty"`
	Subscriptions []twocloud.Subscription `json:"subscriptions,omitempty"`
	Users         []twocloud.User         `json:"users,omitempty"`
	Credentials   *Credentials            `json:"credentials,omitempty"`
}

func Respond(w http.ResponseWriter, code int, msg string, elems []interface{}) {
	resp := Response{}
	resp.Code = code
	resp.Message = msg
	contentTypes := map[string]bool{}
	for _, elem := range elems {
		switch d := elem.(type) {
		case twocloud.Account:
			resp.Accounts = append(resp.Accounts, d)
			contentTypes["accounts"] = true
			break
		case *twocloud.Account:
			resp.Accounts = append(resp.Accounts, *d)
			contentTypes["accounts"] = true
			break
		case []twocloud.Account:
			resp.Accounts = append(resp.Accounts, d...)
			contentTypes["accounts"] = true
			break
		case []*twocloud.Account:
			for _, account := range d {
				resp.Accounts = append(resp.Accounts, *account)
			}
			contentTypes["accounts"] = true
			break
		case twocloud.Device:
			resp.Devices = append(resp.Devices, d)
			contentTypes["devices"] = true
			break
		case *twocloud.Device:
			resp.Devices = append(resp.Devices, *d)
			contentTypes["devices"] = true
			break
		case []twocloud.Device:
			resp.Devices = append(resp.Devices, d...)
			contentTypes["devices"] = true
			break
		case []*twocloud.Device:
			for _, device := range d {
				resp.Devices = append(resp.Devices, *device)
			}
			contentTypes["devices"] = true
			break
		case twocloud.Link:
			resp.Links = append(resp.Links, d)
			contentTypes["links"] = true
			break
		case *twocloud.Link:
			resp.Links = append(resp.Links, *d)
			contentTypes["links"] = true
			break
		case []twocloud.Link:
			resp.Links = append(resp.Links, d...)
			contentTypes["links"] = true
			break
		case []*twocloud.Link:
			for _, link := range d {
				resp.Links = append(resp.Links, *link)
			}
			contentTypes["links"] = true
			break
		case twocloud.Notification:
			resp.Notifications = append(resp.Notifications, d)
			contentTypes["notifications"] = true
			break
		case *twocloud.Notification:
			resp.Notifications = append(resp.Notifications, *d)
			contentTypes["notifications"] = true
			break
		case []twocloud.Notification:
			resp.Notifications = append(resp.Notifications, d...)
			contentTypes["notifications"] = true
			break
		case []*twocloud.Notification:
			for _, n := range d {
				resp.Notifications = append(resp.Notifications, *n)
			}
			contentTypes["notifications"] = true
			break
		case twocloud.Subscription:
			resp.Subscriptions = append(resp.Subscriptions, d)
			contentTypes["subscriptions"] = true
			break
		case *twocloud.Subscription:
			resp.Subscriptions = append(resp.Subscriptions, *d)
			contentTypes["subscriptions"] = true
			break
		case []twocloud.Subscription:
			resp.Subscriptions = append(resp.Subscriptions, d...)
			contentTypes["subscriptions"] = true
			break
		case []*twocloud.Subscription:
			for _, s := range d {
				resp.Subscriptions = append(resp.Subscriptions, *s)
			}
			contentTypes["subscriptions"] = true
			break
		case twocloud.User:
			resp.Users = append(resp.Users, d)
			contentTypes["users"] = true
			break
		case *twocloud.User:
			resp.Users = append(resp.Users, *d)
			contentTypes["users"] = true
			break
		case []twocloud.User:
			resp.Users = append(resp.Users, d...)
			contentTypes["users"] = true
		case []*twocloud.User:
			for _, u := range d {
				resp.Users = append(resp.Users, *u)
			}
			contentTypes["users"] = true
		case Credentials:
			contentTypes["credentials"] = true
			resp.Credentials = &d
		case *Credentials:
			contentTypes["credentials"] = true
			resp.Credentials = d
		}
	}
	contentType := "application"
	if len(contentTypes) > 1 {
		contentType = "mixed:"
	} else if len(contentTypes) == 1 {
		contentType = ""
	}
	sortedContentTypes := make([]string, len(contentTypes))
	i := 0
	for k, _ := range contentTypes {
		sortedContentTypes[i] = k
		i++
	}
	sort.Strings(sortedContentTypes)
	contentType = contentType + strings.Join(sortedContentTypes, ",") + "/json"
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	err := enc.Encode(resp)
	if err != nil {
		os.Stdout.WriteString(err.Error()+"\n")
	}
}
