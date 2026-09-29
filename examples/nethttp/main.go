// Command nethttp demonstrates host-owned browser transport and bearer-only API
// routes backed by a single PostgreSQL Runtime.
package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

//go:embed index.html
var page []byte

//go:embed app.js
var script []byte

func main() {
	if err := run(); err != nil {
		log.Print("example stopped: ", err)
		os.Exit(1)
	}
}

func key(name string) (goauth.KeyRing, error) {
	material, err := base64.StdEncoding.DecodeString(os.Getenv(name))
	if err != nil || len(material) != 32 {
		return goauth.KeyRing{}, fmt.Errorf("%s must contain a base64 encoded 32 byte key", name)
	}
	return goauth.NewKeyRing(name+"-v1", goauth.Key{ID: name + "-v1", Material: material})
}

func run() error {
	if os.Getenv("GENERATE_KEYS") == "1" {
		return generateKeys()
	}
	runtime, origin, dev, err := configureRuntime()
	if err != nil {
		return err
	}
	defer func() { _ = runtime.Close() }()
	return serve(runtime, origin, dev)
}

func generateKeys() error {
	for _, name := range []string{"JWT_KEY", "TOKEN_KEY", "OUTBOX_KEY"} {
		data := make([]byte, 32)
		if _, err := rand.Read(data); err != nil {
			return errors.New("generate keys")
		}
		if _, err := fmt.Fprintf(os.Stdout, "export %s='%s'\n", name, base64.StdEncoding.EncodeToString(data)); err != nil {
			return err
		}
	}
	return nil
}

func configureRuntime() (*postgres.Runtime, string, bool, error) {
	origin := os.Getenv("PUBLIC_ORIGIN")
	if origin == "" {
		origin = "https://localhost:8443"
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" || parsed.User != nil {
		return nil, "", false, errors.New("PUBLIC_ORIGIN must be an absolute origin")
	}
	dev := os.Getenv("LOCALHOST_DEV") == "1"
	localhost := parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1"
	if dev && !localhost {
		return nil, "", false, errors.New("LOCALHOST_DEV requires a localhost origin")
	}
	if parsed.Scheme != "https" && (!dev || parsed.Scheme != "http" || !localhost) {
		return nil, "", false, errors.New("HTTPS required; LOCALHOST_DEV=1 permits HTTP localhost")
	}
	signing, err := key("JWT_KEY")
	if err != nil {
		return nil, "", false, err
	}
	token, err := key("TOKEN_KEY")
	if err != nil {
		return nil, "", false, err
	}
	outbox, err := key("OUTBOX_KEY")
	if err != nil {
		return nil, "", false, err
	}
	smtpAddress := os.Getenv("SMTP_ADDR")
	if smtpAddress == "" {
		smtpAddress = "127.0.0.1:1025"
	}
	// This example intentionally sends only to a local SMTP catcher.
	smtpHost, _, err := net.SplitHostPort(smtpAddress)
	if err != nil || (smtpHost != "localhost" && smtpHost != "127.0.0.1") {
		return nil, "", false, errors.New("SMTP_ADDR must address the local development catcher")
	}
	runtime, err := postgres.NewRuntime(postgres.Config{
		DSN:         os.Getenv("DATABASE_URL"),
		AutoMigrate: true,
		NotificationSender: goauth.NotificationSenderFunc(func(ctx context.Context, delivery goauth.NotificationDelivery) error {
			return sendMail(ctx, smtpAddress, delivery)
		}), Runtime: goauth.Config{
			Signing:        goauth.SigningConfig{Issuer: origin, Audience: "nethttp-example", Keys: signing},
			TokenHMACKeys:  token,
			OutboxAEADKeys: outbox,
			URLBuilder: goauth.URLBuilderFunc(func(_ context.Context, token string) (string, error) {
				return origin + "/#reset=" + url.QueryEscape(token), nil
			}),
		},
	})
	if err != nil {
		return nil, "", false, errors.New("initialize PostgreSQL Runtime failed (check database and key configuration)")
	}
	return runtime, origin, dev, nil
}

func serve(runtime *postgres.Runtime, _ string, dev bool) error {
	handler, err := newHandler(runtime, true)
	if dev {
		handler, err = newHandler(runtime, false)
	}
	if err != nil {
		return err
	}
	listen := os.Getenv("LISTEN_ADDR")
	if listen == "" {
		listen = "127.0.0.1:8443"
	}
	if dev && os.Getenv("LISTEN_ADDR") == "" {
		listen = "127.0.0.1:8080"
	}
	server := &http.Server{
		Addr: listen, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	failures := make(chan error, 3)
	var workers sync.WaitGroup
	workers.Go(func() {
		if err := runtime.RunNotifications(ctx); err != nil && ctx.Err() == nil {
			failures <- errors.New("notification worker failed")
		}
	})
	workers.Go(func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := runtime.Cleanup(ctx, postgres.DefaultCleanupPolicy()); err != nil && ctx.Err() == nil {
					failures <- errors.New("cleanup failed")
					return
				}
			}
		}
	})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		var err error
		if dev {
			err = server.ListenAndServe()
		} else {
			err = server.ListenAndServeTLS(os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"))
		}
		if !errors.Is(err, http.ErrServerClosed) {
			failures <- errors.New("HTTP listener failed (check address and TLS files)")
		}
	}()
	log.Print("example HTTP listener started")
	var result error
	select {
	case <-ctx.Done():
	case result = <-failures:
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		if result == nil {
			result = errors.New("HTTP graceful shutdown timed out")
		}
	}
	cancel()
	workers.Wait()
	<-serverDone
	return result
}

func sendMail(ctx context.Context, address string, delivery goauth.NotificationDelivery) error {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return errors.New("connect local SMTP")
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	client, err := smtp.NewClient(conn, "localhost")
	if err != nil {
		return errors.New("SMTP greeting")
	}
	defer func() { _ = client.Close() }()
	if err = client.Mail("auth@example.test"); err != nil {
		return errors.New("SMTP sender")
	}
	if err = client.Rcpt(delivery.Notification.To); err != nil {
		return errors.New("SMTP recipient")
	}
	writer, err := client.Data()
	if err != nil {
		return errors.New("SMTP data")
	}
	data, err := json.MarshalIndent(delivery.Notification.Data, "", "  ")
	if err != nil {
		return errors.New("encode notification")
	}
	recipient := strings.ReplaceAll(strings.ReplaceAll(delivery.Notification.To, "\r", ""), "\n", "")
	message := "From: auth@example.test\r\nTo: " + recipient +
		"\r\nSubject: goauth notification\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + string(data) + "\r\n"
	if _, err = io.WriteString(writer, message); err != nil {
		return errors.New("SMTP write")
	}
	if err = writer.Close(); err != nil {
		return errors.New("SMTP finish")
	}
	if err = client.Quit(); err != nil {
		return errors.New("SMTP quit")
	}
	return nil
}
