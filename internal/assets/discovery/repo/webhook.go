package repo

import (
	"encoding/json"
	"io"
	"net/http"
)

// Publisher abstracts the message broker (e.g. NATS)
type Publisher interface {
	Publish(subject string, data []byte) error
}

type WebhookHandler struct {
	Publisher Publisher
	Subject   string
}

// GitHubPushEvent is a simplified struct for a GitHub push event payload.
type GitHubPushEvent struct {
	Repository struct {
		CloneURL string `json:"clone_url"`
	} `json:"repository"`
	Commits []struct {
		Added    []string `json:"added"`
		Modified []string `json:"modified"`
	} `json:"commits"`
}

func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var event GitHubPushEvent
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "Failed to parse JSON", http.StatusBadRequest)
		return
	}

	var allFiles []string
	for _, c := range event.Commits {
		allFiles = append(allFiles, c.Added...)
		allFiles = append(allFiles, c.Modified...)
	}

	ecosystems := DetectEcosystems(allFiles)

	sig := RepoSignalEvent{
		Type:            "repo",
		URL:             event.Repository.CloneURL,
		ConfidenceScore: 1.0, // webhooks are highly confident
		Ecosystems:      ecosystems,
	}

	data, err := json.Marshal(sig)
	if err != nil {
		http.Error(w, "Failed to marshal signal", http.StatusInternalServerError)
		return
	}

	if err := h.Publisher.Publish(h.Subject, data); err != nil {
		http.Error(w, "Failed to publish signal", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
