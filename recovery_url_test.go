//nolint:testpackage // Checks the private guard for trusted URLBuilder output.
package goauth

import "testing"

func TestPasswordResetURLPolicy(t *testing.T) {
	for _, value := range []string{
		"https://auth.example.test/reset?token=synthetic",
		"https://auth.example.test/#reset=synthetic",
		"http://localhost:8080/#reset=synthetic",
	} {
		if err := validatePasswordResetURL(value); err != nil {
			t.Errorf("supported URL rejected: %s: %v", value, err)
		}
	}
	for _, value := range []string{
		"/reset?token=synthetic",
		"http://auth.example.test/reset",
		"https://user:synthetic@auth.example.test/reset",
		"https://auth.example.test/reset?email=person%40example.test",
		"https://auth.example.test/#reset=%zz",
	} {
		if err := validatePasswordResetURL(value); err == nil {
			t.Errorf("unsafe URL accepted: %s", value)
		}
	}
}
