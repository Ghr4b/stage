package msgbus

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestJetStreamDeliversPersistedScanRequest(t *testing.T) {
	url := os.Getenv("NATS_TEST_URL")
	if url == "" {
		t.Skip("set NATS_TEST_URL to run the JetStream integration test")
	}

	publisher, err := NewNATSClient(url)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"asset_id":"jetstream-integration-test","canonical_name":"jetstream-integration-test"}`)
	if err := publisher.Publish("tijeri.scan.requested", payload); err != nil {
		publisher.Close()
		t.Fatal(err)
	}
	publisher.Close()

	consumer, err := NewNATSClient(url)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()

	delivered := make(chan []byte, 1)
	if err := consumer.Subscribe("tijeri.scan.requested", func(message []byte) error {
		delivered <- message
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	select {
	case received := <-delivered:
		if string(received) != string(payload) {
			t.Fatalf("received payload %s, want %s", received, payload)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for persisted scan request")
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		info, err := consumer.js.ConsumerInfo(scanJobStream, durableConsumerName("tijeri.scan.requested"))
		if err == nil && info.NumAckPending == 0 && info.NumPending == 0 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("timed out waiting for scan request acknowledgement")
}

func TestJetStreamDeadLettersAfterDeliveryLimit(t *testing.T) {
	url := os.Getenv("NATS_TEST_URL")
	if url == "" {
		t.Skip("set NATS_TEST_URL to run the JetStream integration test")
	}

	client, err := NewNATSClient(url)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	deadLetters, err := client.js.SubscribeSync(deadLetterSubject,
		nats.Durable("TIJERI_TEST_DEAD_LETTER"), nats.ManualAck(), nats.AckWait(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer deadLetters.Unsubscribe()

	failedDeliveries := make(chan struct{}, int(maxJobDeliveries))
	if err := client.Subscribe("tijeri.asset.discovered", func([]byte) error {
		failedDeliveries <- struct{}{}
		return context.DeadlineExceeded
	}); err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"asset_id":"dead-letter-integration-test","canonical_name":"dead-letter-integration-test"}`)
	if err := client.Publish("tijeri.asset.discovered", payload); err != nil {
		t.Fatal(err)
	}
	message, err := deadLetters.NextMsg(35 * time.Second)
	if err != nil {
		t.Fatalf("waiting for dead-letter: %v", err)
	}
	var result deadLetter
	if err := json.Unmarshal(message.Data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Subject != "tijeri.asset.discovered" || result.Deliveries != maxJobDeliveries || string(result.Payload) != string(payload) {
		t.Fatalf("unexpected dead-letter record: %+v", result)
	}
	if err := message.Ack(); err != nil {
		t.Fatal(err)
	}
	if got := len(failedDeliveries); got != int(maxJobDeliveries) {
		t.Fatalf("handler ran %d times, want %d", got, maxJobDeliveries)
	}
}
