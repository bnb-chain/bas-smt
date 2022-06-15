package database

import "errors"

var (
	// ErrDatabaseClosed is returned if a database was already closed at the
	// invocation of a data access operation.
	ErrDatabaseClosed = errors.New("database closed")

	// ErrDatabaseNotFound is returned if a key is requested that is not found in
	// the provided database.
	ErrDatabaseNotFound = errors.New("key not found")
)
