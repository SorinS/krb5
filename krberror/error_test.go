package krberror

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorf(t *testing.T) {
	err := fmt.Errorf("an error")

	var a Krberror

	a = Errorf(err, "cause", "some text")
	assert.Equal(t, "[Root cause: cause] cause: some text: an error", a.Error())
	a = Errorf(err, "cause", "arg1=%d arg2=%s", 123, "arg")
	assert.Equal(t, "[Root cause: cause] cause: arg1=123 arg2=arg: an error", a.Error())

	err = NewErrorf("another error", "some text")
	a = Errorf(err, "cause", "some text")
	assert.Equal(t, "[Root cause: another error] cause: some text < another error: some text", a.Error())
	a = Errorf(err, "cause", "arg1=%d arg2=%s", 123, "arg")
	assert.Equal(t, "[Root cause: another error] cause: arg1=123 arg2=arg < another error: some text", a.Error())
}

type codeError struct{ code int }

func (e codeError) Error() string { return "code" }

// Errorf keeps the error it wraps, for errors.As and errors.Is, through
// any number of Errorf calls.
func TestErrorf_Unwrap(t *testing.T) {
	t.Parallel()

	inner := codeError{code: 37}
	err := Errorf(inner, KDCError, "first")
	err = Errorf(err, KRBMsgError, "second")

	var ce codeError
	assert.True(t, errors.As(err, &ce))
	assert.Equal(t, 37, ce.code)
	assert.ErrorIs(t, err, inner)
	assert.Contains(t, err.Error(), "first")
	assert.Contains(t, err.Error(), "second")

	assert.NoError(t, New(KDCError, "no inner").Unwrap())
}
