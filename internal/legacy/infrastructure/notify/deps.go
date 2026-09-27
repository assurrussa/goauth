package notify

import (
	"context"

	"github.com/assurrussa/gonotify"
)

type (
	NotificationLevel    = gonotify.NotificationLevel
	NotificationChannel  = gonotify.NotificationChannel
	Notification         = gonotify.Notification
	Recipient            = gonotify.Recipient
	NotificationResult   = gonotify.NotificationResult
	NotificationContract = gonotify.NotificationContract
	NotificationManager  = gonotify.NotificationManager
	NotificationSender   = gonotify.NotificationSender
)

const (
	LevelInfo     = gonotify.LevelInfo
	LevelWarning  = gonotify.LevelWarning
	LevelError    = gonotify.LevelError
	LevelCritical = gonotify.LevelCritical

	ChannelEmail    = gonotify.ChannelEmail
	ChannelTelegram = gonotify.ChannelTelegram
)

func NewNotification(level NotificationLevel, title, message string) *Notification {
	return gonotify.NewNotification(level, title, message)
}

func NewRecipient(id, name string) *Recipient {
	return gonotify.NewRecipient(id, name)
}

type NoopNotificationService struct{}

func (NoopNotificationService) SendToChannel(
	context.Context,
	NotificationChannel,
	*Notification,
	...*Recipient,
) ([]*NotificationResult, error) {
	return nil, nil
}
