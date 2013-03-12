package main

type Error struct {
	Code  int    `json:"code,omitempty"`
	Item  int    `json:"item,omitempty"`
	Field string `json:"field,omitempty"`
}

var (
	// Error codes
	ERROR_ACCESS_DENIED_CODE      = 1
	ERROR_INVALID_FORMAT_CODE     = 2
	ERROR_MISSING_PARAM_CODE      = 3
	ERROR_NOT_FOUND_CODE          = 4
	ERROR_BAD_REQUEST_FORMAT_CODE = 5
	ERROR_ALREADY_IN_USE_CODE     = 6
	ERROR_TOO_SHORT_CODE          = 7
	ERROR_TOO_LONG_CODE           = 8
	ERROR_INVALID_VALUE_CODE      = 9
	ERROR_ACT_OF_GOD_CODE         = 10 // Used for things entirely outside our control
	ERROR_WRONG_OWNER_CODE        = 11
)

func AccessDenied(field string) error {
}

func AccessDeniedOnItem(field string, item int) error {
}
