package ldap

import "github.com/FatmanUK/olivine_ldap/internal/ber"

// nextString reads the next element's contents as a string.
func nextString(d *ber.Decoder) (string, error) {
	_, content, err := d.Next()
	if err != nil {
		return "", ErrBadRequest
	}
	return string(content), nil
}

// nextInt reads the next element as an int32.
func nextInt(d *ber.Decoder) (int32, error) {
	_, content, err := d.Next()
	if err != nil {
		return 0, ErrBadRequest
	}
	n, err := ber.Int32(content)
	if err != nil {
		return 0, ErrBadRequest
	}
	return n, nil
}

// nextBool reads the next element as a boolean.
func nextBool(d *ber.Decoder) (bool, error) {
	_, content, err := d.Next()
	if err != nil {
		return false, ErrBadRequest
	}
	v, err := ber.Bool(content)
	if err != nil {
		return false, ErrBadRequest
	}
	return v, nil
}
