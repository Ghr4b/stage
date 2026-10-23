package msgbus

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	scanJobStream      = "TIJERI_SCAN_JOBS"
	deadLetterSubject  = "tijeri.dead-letter"
	maxJobDeliveries   = uint64(5)
	scanJobAckWait     = 5 * time.Minute
	scanJobRetryDelay  = 5 * time.Second
	scanJobMaxAge      = 30 * 24 * time.Hour
	scanJobMaxBytes    = int64(4 * 1024 * 1024 * 1024)
	scanJobMaxPending  = 64
	scanJobQueuePolicy = nats.WorkQueuePolicy
)

var durableJobSubjects = []string{
	"tijeri.asset.discovered",
	"tijeri.scan.requested",
	deadLetterSubject,
}

type deadLetter struct {
	Subject     string    `json:"subject"`
	Payload     []byte    `json:"payload"`
	Reason      string    `json:"reason"`
	Deliveries  uint64    `json:"deliveries"`
	FailedAtUTC time.Time `json:"failed_at_utc"`
}

type NATSClient struct {
	conn *nats.Conn
	js   nats.JetStreamContext
}

func NewNATSClient(url string) (*NATSClient, error) {
	if url == "" {
		return nil, errors.New("NATS URL is required")
	}
	nc, err := nats.Connect(url)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("failed to initialize NATS JetStream: %w", err)
	}
	if err := ensureScanJobStream(js); err != nil {
		nc.Close()
		return nil, fmt.Errorf("failed to configure durable scan-job stream: %w", err)
	}
	log.Printf("Successfully connected to NATS")
	return &NATSClient{conn: nc, js: js}, nil
}

func ensureScanJobStream(js nats.JetStreamContext) error {
	config := &nats.StreamConfig{
		Name:       scanJobStream,
		Subjects:   append([]string(nil), durableJobSubjects...),
		Retention:  scanJobQueuePolicy,
		Storage:    nats.FileStorage,
		MaxAge:     scanJobMaxAge,
		MaxBytes:   scanJobMaxBytes,
		MaxMsgs:    -1,
		Discard:    nats.DiscardNew,
		Replicas:   1,
		Duplicates: 2 * time.Minute,
	}
	info, err := js.StreamInfo(scanJobStream)
	if errors.Is(err, nats.ErrStreamNotFound) {
		_, err = js.AddStream(config)
		if err == nil {
			return nil
		}
		info, err = js.StreamInfo(scanJobStream)
	}
	if err != nil {
		return err
	}
	if info.Config.Retention != scanJobQueuePolicy || info.Config.Storage != nats.FileStorage ||
		info.Config.Discard != nats.DiscardNew || info.Config.MaxAge <= 0 || info.Config.MaxBytes <= 0 {
		return errors.New("existing stream must use file storage, work-queue retention, a finite age and size limit, and discard-new overflow handling")
	}
	for _, subject := range durableJobSubjects {
		found := false
		for _, configured := range info.Config.Subjects {
			if configured == subject {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("existing stream is missing required subject %s", subject)
		}
	}
	return nil
}

func (c *NATSClient) Subscribe(subject string, handler func(msg []byte) error) error {
	if !isDurableJobSubject(subject) || subject == deadLetterSubject {
		return fmt.Errorf("subject %s is not a consumable scan-job subject", subject)
	}
	maxPending := scanJobMaxPending
	durable := durableConsumerName(subject)
	if info, err := c.js.ConsumerInfo(scanJobStream, durable); err == nil {
		config := info.Config
		config.AckPolicy = nats.AckExplicitPolicy
		config.AckWait = scanJobAckWait
		config.MaxDeliver = -1
		config.MaxAckPending = maxPending
		if _, err := c.js.UpdateConsumer(scanJobStream, &config); err != nil {
			return fmt.Errorf("failed to update durable consumer %s: %w", durable, err)
		}
	} else if !errors.Is(err, nats.ErrConsumerNotFound) {
		return fmt.Errorf("failed to inspect durable consumer %s: %w", durable, err)
	}
	_, err := c.js.QueueSubscribe(subject, durable, func(message *nats.Msg) {
		payload := append([]byte(nil), message.Data...)
		go c.processMessage(message, subject, payload, handler)
	}, nats.Durable(durable), nats.ManualAck(), nats.AckWait(scanJobAckWait),
		nats.MaxDeliver(-1), nats.MaxAckPending(maxPending))
	if err != nil {
		return fmt.Errorf("failed to bind durable consumer for %s: %w", subject, err)
	}
	return nil
}

func (c *NATSClient) processMessage(message *nats.Msg, subject string, payload []byte, handler func([]byte) error) {
	stopHeartbeat := make(chan struct{})
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stopHeartbeat:
				return
			case <-ticker.C:
				if err := message.InProgress(); err != nil {
					log.Printf("NATS job acknowledgement heartbeat failed for %s: %v", subject, err)
				}
			}
		}
	}()
	processingErr := handler(payload)
	close(stopHeartbeat)
	<-heartbeatDone
	if processingErr == nil {
		if err := message.AckSync(); err != nil {
			log.Printf("NATS job acknowledgement failed for %s: %v", subject, err)
		}
		return
	}
	metadata, err := message.Metadata()
	if err == nil && metadata.NumDelivered >= maxJobDeliveries {
		if err := c.publishDeadLetter(subject, payload, processingErr.Error(), metadata.NumDelivered); err == nil {
			if err := message.AckSync(); err != nil {
				log.Printf("NATS dead-letter acknowledgement failed for %s: %v", subject, err)
			}
			return
		} else {
			log.Printf("NATS dead-letter publish failed for %s: %v", subject, err)
		}
	}
	if err := message.NakWithDelay(scanJobRetryDelay); err != nil {
		log.Printf("NATS job retry scheduling failed for %s: %v", subject, err)
	}
}

func (c *NATSClient) publishDeadLetter(subject string, payload []byte, reason string, deliveries uint64) error {
	data, err := json.Marshal(deadLetter{
		Subject:     subject,
		Payload:     payload,
		Reason:      reason,
		Deliveries:  deliveries,
		FailedAtUTC: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	_, err = c.js.Publish(deadLetterSubject, data)
	return err
}

func isDurableJobSubject(subject string) bool {
	return subject == "tijeri.asset.discovered" || subject == "tijeri.scan.requested" || subject == deadLetterSubject
}

func durableConsumerName(subject string) string {
	return "TIJERI_" + strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(subject))
}

func (c *NATSClient) Publish(subject string, data []byte) error {
	if isDurableJobSubject(subject) && subject != deadLetterSubject {
		if _, err := c.js.Publish(subject, data); err != nil {
			return fmt.Errorf("failed to persist event on subject %s: %w", subject, err)
		}
		return nil
	}
	if err := c.conn.Publish(subject, data); err != nil {
		return fmt.Errorf("failed to publish to subject %s: %w", subject, err)
	}
	if err := c.conn.FlushTimeout(5 * time.Second); err != nil {
		return fmt.Errorf("failed to flush event on subject %s: %w", subject, err)
	}
	return nil
}

func (c *NATSClient) Connected() bool {
	return c.conn != nil && c.conn.IsConnected() && c.js != nil
}

// Close gracefully closes the NATS connection.
func (c *NATSClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}
