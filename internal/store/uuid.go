package store

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
)

// normalizeUUID converts arbitrary asset/finding IDs to valid UUIDs.
// IDs that are already UUIDs are returned unchanged; everything else is
// deterministically mapped (SHA-1 derived, UUIDv5-style) so the same ID
// always yields the same UUID across retries and re-discovery.
func normalizeUUID(id string) string {
	if isUUID(id) {
		return id
	}
	h := sha1.Sum([]byte(id))
	h[6] = (h[6] & 0x0f) | 0x50
	h[8] = (h[8] & 0x3f) | 0x80
	raw := hex.EncodeToString(h[:16])
	return raw[0:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:32]
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}