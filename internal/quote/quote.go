// Package quote removes quoted reply history from a message body so an agent
// does not pay tokens for the same thread on every reply.
//
// The package is pure: it takes a decoded body and returns a shorter one. It
// prefers keeping text over removing it. Anything it cannot recognise with
// confidence stays, and a body that would become empty comes back unchanged.
package quote

// Result is a stripped body and what was taken out of it.
//
// RemovedBytes and RemovedLines count the original content that was removed.
// They do not subtract the placeholder lines StripText inserts. When nothing
// was removed, Text is the input and both counts are zero.
type Result struct {
	Text         string
	RemovedBytes int
	RemovedLines int
	// TooLarge is set when the body is over MaxBytes and was not looked at.
	TooLarge bool
}

// MaxBytes is the largest body the strippers read. A larger body comes back
// unchanged with TooLarge set, so a hostile message cannot cost much CPU.
const MaxBytes = 2 << 20

func tooLarge(body string) Result { return Result{Text: body, TooLarge: true} }

func unchanged(body string) Result { return Result{Text: body} }
