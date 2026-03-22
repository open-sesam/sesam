package core

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"filippo.io/age"
)

// TODO: Later we should pass users in here so we know which users can use which public keys.
//
//	That mapping should then match with the
//
// TODO: That is a very dumb algorithm. It has only been chosen because it was somewhat foolproof.
func MatchIdentitiesToRecipients(ids []age.Identity, rps []age.Recipient) error {
	const dummyText = "sesam"

	rpTexts := make([]string, len(rps))
	for idx, rp := range rps {
		buf := &bytes.Buffer{}
		w, _ := age.Encrypt(buf, rp)
		_, _ = w.Write([]byte(dummyText))
		_ = w.Close()
		rpTexts[idx] = buf.String()
	}

	for idx, rpText := range rpTexts {
		for _, id := range ids {
			r, err := age.Decrypt(strings.NewReader(rpText), id)
			if err != nil {
				// most likely not matching.
				continue
			}

			resp, _ := io.ReadAll(r)
			if string(resp) != dummyText {
				slog.Warn("could decrypt fake message, but not the right content")
				continue
			}

			fmt.Println(id, rpTexts[idx])
		}
	}

	return nil
}
