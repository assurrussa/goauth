package postgres_test

import (
	"strings"
	"testing"
)

func TestBackupFixtureURL(t *testing.T) {
	const valid = "postgres://goauth:goauth@127.0.0.1:55433/goauth_integration?sslmode=disable"
	for _, tc := range []struct {
		name, raw, port, project string
		valid                    bool
	}{
		{"isolated", valid, "55433", "goauth-v02-integration-backup", true},
		{"default", strings.ReplaceAll(valid, "55433", "55432"), "55432", backupFixtureProject, true},
		{"remote", strings.ReplaceAll(valid, "127.0.0.1", "db.example.test"), "55433", backupFixtureProject, false},
		{"localhost", strings.ReplaceAll(valid, "127.0.0.1", "localhost"), "55433", backupFixtureProject, false},
		{"wrong port", valid, "55434", backupFixtureProject, false},
		{"database", strings.ReplaceAll(valid, "goauth_integration", "application"), "55433", backupFixtureProject, false},
		{"credentials", strings.ReplaceAll(valid, "goauth:goauth@", "admin:secret@"), "55433", backupFixtureProject, false},
		{"host override", valid + "&host=remote", "55433", backupFixtureProject, false},
		{"hostaddr override", valid + "&hostaddr=192.0.2.1", "55433", backupFixtureProject, false},
		{"unrelated project", valid, "55433", "application", false},
		{"empty suffix", valid, "55433", backupFixtureProject + "-", false},
		{"bad port", valid, "055433", backupFixtureProject, false},
		{"privileged port", valid, "543", backupFixtureProject, false},
		{"port overflow", valid, "65536", backupFixtureProject, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := backupFixtureURL(tc.raw, tc.port, tc.project)
			if (err == nil) != tc.valid {
				t.Fatalf("valid = %v, error = %v", tc.valid, err)
			}
		})
	}
}

func TestBackupFixtureContainer(t *testing.T) {
	const valid = `[{"Id":"owned","State":{"Running":true},"Config":{"Labels":{"com.docker.compose.project":"goauth-v02-integration-backup","com.docker.compose.service":"postgres","com.docker.compose.oneoff":"False"},"Env":["POSTGRES_DB=goauth_integration","POSTGRES_USER=goauth","POSTGRES_PASSWORD=goauth"]},"NetworkSettings":{"Ports":{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"55433"}]}}}]`
	for _, tc := range []struct {
		name, data string
		valid      bool
	}{
		{"owned fixture", valid, true},
		{"different container", strings.ReplaceAll(valid, "owned", "other"), false},
		{"stopped", strings.ReplaceAll(valid, "true", "false"), false},
		{"different project", strings.ReplaceAll(valid, "goauth-v02-integration-backup", "application"), false},
		{"different service", strings.ReplaceAll(valid, `"postgres"`, `"application"`), false},
		{"oneoff", strings.ReplaceAll(valid, "False", "True"), false},
		{"different database", strings.ReplaceAll(valid, "goauth_integration", "application"), false},
		{"different user", strings.ReplaceAll(valid, "POSTGRES_USER=goauth", "POSTGRES_USER=admin"), false},
		{"different password", strings.ReplaceAll(valid, "POSTGRES_PASSWORD=goauth", "POSTGRES_PASSWORD=secret"), false},
		{"public binding", strings.ReplaceAll(valid, "127.0.0.1", "0.0.0.0"), false},
		{"different port", strings.ReplaceAll(valid, "55433", "55432"), false},
		{"multiple bindings", strings.ReplaceAll(valid, `{"HostIp":"127.0.0.1","HostPort":"55433"}`, `{"HostIp":"127.0.0.1","HostPort":"55433"},{"HostIp":"0.0.0.0","HostPort":"55433"}`), false},
		{"no containers", "[]", false},
		{"multiple containers", "[" + strings.Trim(valid, "[]") + "," + strings.Trim(valid, "[]") + "]", false},
		{"malformed", "{", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBackupContainer([]byte(tc.data), "owned", "goauth-v02-integration-backup", "55433")
			if (err == nil) != tc.valid {
				t.Fatalf("valid = %v, error = %v", tc.valid, err)
			}
		})
	}
}
