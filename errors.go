package bsmt

import "errors"

var (
	ErrEmptyRoot = errors.New("empty root")

	ErrVersionTooOld = errors.New("the version is lower than the rollback version")

	ErrVersionTooHigh = errors.New("the version is higher than the latest version")

	ErrNodeNotFound = errors.New("tree node not found")

	ErrUnexpected = errors.New("unexpected error")

	ErrInvalidKey = errors.New("invalid key")

	ErrInvalidDepth = errors.New("depth must be a multiple of 4")
)
