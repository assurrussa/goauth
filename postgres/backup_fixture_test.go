package postgres_test

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
)

const backupFixtureProject = "goauth-v02-integration"

// Keep the destructive gate tied to the repository's disposable fixture.
func backupFixtureURL(raw, port, project string) (*url.URL, error) {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1024 || n > 65535 || strconv.Itoa(n) != port {
		return nil, errors.New("backup fixture requires a canonical unprivileged TCP port")
	}
	if project != backupFixtureProject && !regexp.MustCompile("^goauth-v02-integration-[a-z0-9][a-z0-9_-]*$").MatchString(project) {
		return nil, errors.New("backup fixture requires a dedicated goauth-v02-integration project")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid backup fixture URL")
	}
	if u.Scheme != "postgres" || u.Host != "127.0.0.1:"+port ||
		u.Path != "/goauth_integration" || u.RawPath != "" ||
		u.RawQuery != "sslmode=disable" || u.Fragment != "" || u.User == nil {
		return nil, errors.New("backup fixture requires the exact loopback goauth_integration URL with sslmode=disable")
	}
	password, ok := u.User.Password()
	if u.User.Username() != "goauth" || !ok || password != "goauth" {
		return nil, errors.New("backup fixture requires disposable goauth credentials")
	}
	return u, nil
}

//nolint:tagliatelle // Docker inspect defines these exact JSON wire names, including Id and HostIp.
type backupContainer struct {
	ID    string `json:"Id"`
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	Config struct {
		Labels map[string]string `json:"Labels"`
		Env    []string          `json:"Env"`
	} `json:"Config"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

func validateBackupContainer(data []byte, id, project, port string) error {
	var containers []backupContainer
	if err := json.Unmarshal(data, &containers); err != nil || len(containers) != 1 {
		return errors.New("backup fixture requires exactly one inspected container")
	}
	c := containers[0]
	if c.ID != id || !c.State.Running ||
		c.Config.Labels["com.docker.compose.project"] != project ||
		c.Config.Labels["com.docker.compose.service"] != "postgres" ||
		c.Config.Labels["com.docker.compose.oneoff"] != "False" {
		return errors.New("backup fixture container identity, state or Compose ownership mismatch")
	}
	for _, expected := range []string{"POSTGRES_DB=goauth_integration", "POSTGRES_USER=goauth", "POSTGRES_PASSWORD=goauth"} {
		found := false
		for _, entry := range c.Config.Env {
			if entry == expected {
				found = true
			}
		}
		if !found {
			return errors.New("backup fixture container configuration mismatch")
		}
	}
	bindings := c.NetworkSettings.Ports["5432/tcp"]
	if len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" || bindings[0].HostPort != port {
		return errors.New("backup fixture must bind only the selected loopback port")
	}
	return nil
}
