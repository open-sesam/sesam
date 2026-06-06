package core

import (
	"context"
	"slices"
	"strings"
	"sync"
)

type SharedPublicKey struct {
	// PubKey is the string version of the key
	PubKey string

	// Users sharing this key.
	// If it's only a single user, then the key is listed more than once.
	Users []string
}

func VerifyKeyReuse(kr Keyring) []SharedPublicKey {
	userMap := kr.ListUsers()
	recpMap := make(map[string][]string)
	for user, recps := range userMap {
		for _, recp := range recps {
			recpStr := recp.String()
			recpMap[recpStr] = append(recpMap[recpStr], user)
		}
	}

	var results []SharedPublicKey
	for recpStr, users := range recpMap {
		if len(users) == 1 {
			continue
		}

		results = append(results, SharedPublicKey{
			PubKey: recpStr,
			Users:  users,
		})
	}

	return results
}

type ForgeReportEntry struct {
	User   string `json:"user"`
	PubKey string `json:"pubkey"`
}

type ForgeReportError struct {
	User   string    `json:"user"`
	Source KeySource `json:"source"`
	Error  error     `json:"error"`
}

type ForgeReport struct {
	// Added are public keys that are in the specified source
	Added []ForgeReportEntry `json:"added,omitempty"`

	// Deleted are public keys that are not anymore in any of the specified sources.
	Deleted []ForgeReportEntry `json:"deleted,omitempty"`

	// Errored are public keys that could not be retrieved at this time any more.
	Errored []ForgeReportError `json:"errored,omitempty"`
}

// VerifyForgeIds checks the public keys of all users and will re-fetch the source they were from.
// Difference to the current state will be highlighted in the returned ForgeReport.
func VerifyForgeIds(ctx context.Context, vstate *VerifiedState, kr Keyring, pluginUI *PluginUI) *ForgeReport {
	currUserMap := make(map[string]Recipients)
	for user, recps := range kr.ListUsers() {
		currUserMap[user] = slices.Clone(recps)
	}

	const nWorkers = 8 // download new keys in parallel
	type job struct {
		Source KeySource
		User   string
	}

	var mapMu sync.Mutex
	errMap := make(map[string][]ForgeReportError)
	newUserMap := make(map[string]Recipients)

	wg := &sync.WaitGroup{}
	wg.Add(nWorkers)

	jobsCh := make(chan job, nWorkers)
	for range nWorkers {
		go func() {
			defer wg.Done()

			for job := range jobsCh {
				newRecps, err := ParseAndResolveRecipients(ctx, []string{string(job.Source)}, pluginUI)
				if err != nil {
					mapMu.Lock()
					errMap[job.User] = append(errMap[job.User], ForgeReportError{
						User:   job.User,
						Source: job.Source,
						Error:  err,
					})
					mapMu.Unlock()
					continue
				}

				mapMu.Lock()
				newUserMap[job.User] = append(newUserMap[job.User], newRecps...)
				mapMu.Unlock()
			}
		}()
	}

	seen := make(map[job]bool)
	for _, user := range vstate.Users {
		for _, recp := range user.Recps {
			if recp.Source == KeySourceManual {
				// if specified in the config, there is no need to check the remote state.
				continue
			}

			j := job{
				Source: recp.Source,
				User:   user.Name,
			}

			if !seen[j] {
				jobsCh <- j
				seen[j] = true
			}
		}
	}

	close(jobsCh)
	wg.Wait()

	report := ForgeReport{}
	for _, errResults := range errMap {
		report.Errored = append(report.Errored, errResults...)

		// delete those from currUserMap so that we later only have those that were deleted.
		for _, errResult := range errResults {
			currRecps, ok := currUserMap[errResult.User]
			if !ok {
				continue
			}

			currUserMap[errResult.User] = slices.DeleteFunc(currRecps, func(recp *Recipient) bool {
				return recp.Source == errResult.Source
			})
		}
	}

	for user, newPubKeys := range newUserMap {
		for _, newPubKey := range newPubKeys {
			currRecps, ok := currUserMap[user]
			if !ok {
				// should usually not happen since both kr and vstate come from the audit log.
				continue
			}

			idx := slices.IndexFunc(currRecps, func(currRecp *Recipient) bool {
				return currRecp.Equal(newPubKey)
			})

			if idx >= 0 {
				// key exists already, remove from curr so we know which are extra.
				currUserMap[user] = slices.Delete(currRecps, idx, idx+1)
				continue
			}

			// Key seems to be new:
			report.Added = append(report.Added, ForgeReportEntry{
				User:   user,
				PubKey: newPubKey.String(),
			})
		}
	}

	for user, leftOverPubKeys := range currUserMap {
		for _, leftOverPubKey := range leftOverPubKeys {
			if leftOverPubKey.Source == KeySourceManual {
				// config keys were not processed and therefore not deleted.
				continue
			}

			report.Deleted = append(report.Deleted, ForgeReportEntry{
				User:   user,
				PubKey: leftOverPubKey.String(),
			})
		}
	}

	sortByUser := func(i, j ForgeReportEntry) int {
		return strings.Compare(i.User, j.User)
	}

	slices.SortStableFunc(report.Added, sortByUser)
	slices.SortStableFunc(report.Deleted, sortByUser)
	slices.SortStableFunc(report.Errored, func(i, j ForgeReportError) int {
		return strings.Compare(i.User, j.User)
	})

	return &report
}
