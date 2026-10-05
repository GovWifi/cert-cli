package pki

import (
	"errors"
	"strings"
	"time"
)

const DateLayout = "2006-01-02"

// DefaultExpiry is the end of the local calendar day 10 years from now.
func DefaultExpiry(now time.Time) time.Time {
	loc := now.Location()
	y, m, d := now.In(loc).Date()
	expiry := time.Date(y, m, d, 0, 0, 0, 0, loc).AddDate(10, 0, 0)
	ey, em, ed := expiry.Date()
	return time.Date(ey, em, ed, 23, 59, 59, 0, loc)
}

// ParseDate parses a YYYY-MM-DD date in now's location and returns the end of
// that local calendar day (23:59:59).
func ParseDate(value string, now time.Time) (time.Time, error) {
	parsed, err := time.ParseInLocation(DateLayout, strings.TrimSpace(value), now.Location())
	if err != nil {
		return time.Time{}, errors.New("value must be a date in YYYY-MM-DD format")
	}
	y, m, d := parsed.Date()
	return time.Date(y, m, d, 23, 59, 59, 0, now.Location()), nil
}

// ResolveExpiryDate uses DefaultExpiry when value is empty.
func ResolveExpiryDate(value string, now time.Time) (time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return DefaultExpiry(now), nil
	}
	return ParseDate(value, now)
}
