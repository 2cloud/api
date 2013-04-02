package main

import (
	"fmt"
)

type Error struct {
	Code  int    `json:"code,omitempty"`
	Item  int    `json:"item,omitempty"`
	Field string `json:"field,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("Error %d: Item #%d, field %s.", e.Code, e.Item, e.Field)
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

func AccessDenied(field string) *Error {
	return AccessDeniedOnItem(field, -1)
}

func AccessDeniedOnItem(field string, item int) *Error {
	err := &Error{
		Code:  ERROR_ACCESS_DENIED_CODE,
		Field: field,
	}
	if item > -1 {
		err.Item = item
	}
	return err
}

func InvalidFormat(field string) *Error {
	return InvalidFormatOnItem(field, -1)
}

func InvalidFormatOnItem(field string, item int) *Error {
	err := &Error{
		Code:  ERROR_INVALID_FORMAT_CODE,
		Field: field,
	}
	if item > -1 {
		err.Item = item
	}
	return err
}

func MissingParam(field string) *Error {
	return MissingParamOnItem(field, -1)
}

func MissingParamOnItem(field string, item int) *Error {
	err := &Error{
		Code:  ERROR_MISSING_PARAM_CODE,
		Field: field,
	}
	if item > -1 {
		err.Item = item
	}
	return err
}

func NotFound(field string) *Error {
	return NotFoundOnItem(field, -1)
}

func NotFoundOnItem(field string, item int) *Error {
	err := &Error{
		Code:  ERROR_NOT_FOUND_CODE,
		Field: field,
	}
	if item > -1 {
		err.Item = item
	}
	return err
}

func BadRequestFormat(field string) *Error {
	return BadRequestFormatOnItem(field, -1)
}

func BadRequestFormatOnItem(field string, item int) *Error {
	err := &Error{
		Code:  ERROR_BAD_REQUEST_FORMAT_CODE,
		Field: field,
	}
	if item > -1 {
		err.Item = item
	}
	return err
}

func AlreadyInUse(field string) *Error {
	return AlreadyInUseOnItem(field, -1)
}

func AlreadyInUseOnItem(field string, item int) *Error {
	err := &Error{
		Code:  ERROR_ALREADY_IN_USE_CODE,
		Field: field,
	}
	if item > -1 {
		err.Item = item
	}
	return err
}

func TooShort(field string) *Error {
	return TooShortOnItem(field, -1)
}

func TooShortOnItem(field string, item int) *Error {
	err := &Error{
		Code:  ERROR_TOO_SHORT_CODE,
		Field: field,
	}
	if item > -1 {
		err.Item = item
	}
	return err
}

func TooLong(field string) *Error {
	return TooLongOnItem(field, -1)
}

func TooLongOnItem(field string, item int) *Error {
	err := &Error{
		Code:  ERROR_TOO_LONG_CODE,
		Field: field,
	}
	if item > -1 {
		err.Item = item
	}
	return err
}

func InvalidValue(field string) *Error {
	return InvalidValueOnItem(field, -1)
}

func InvalidValueOnItem(field string, item int) *Error {
	err := &Error{
		Code:  ERROR_INVALID_VALUE_CODE,
		Field: field,
	}
	if item > -1 {
		err.Item = item
	}
	return err
}

func ActOfGod(field string) *Error {
	return ActOfGodOnItem(field, -1)
}

func ActOfGodOnItem(field string, item int) *Error {
	err := &Error{
		Code:  ERROR_ACT_OF_GOD_CODE,
		Field: field,
	}
	if item > -1 {
		err.Item = item
	}
	return err
}

func WrongOwner(field string) *Error {
	return WrongOwnerOnItem(field, -1)
}

func WrongOwnerOnItem(field string, item int) *Error {
	err := &Error{
		Code:  ERROR_WRONG_OWNER_CODE,
		Field: field,
	}
	if item > -1 {
		err.Item = item
	}
	return err
}
