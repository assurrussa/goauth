package notifications

import (
	notifications "github.com/assurrussa/gonotify/interfaces/outbox/notifications"
)

const JobName = notifications.JobName

type Payload = notifications.Payload

func MarshalPayload(payload Payload) (string, error) {
	return notifications.MarshalPayload(payload)
}

func UnmarshalPayload(raw string) (Payload, error) {
	return notifications.UnmarshalPayload(raw)
}
