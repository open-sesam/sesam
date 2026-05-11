package repo

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/format/pktline"
	"github.com/stretchr/testify/require"
)

// runHandler drives FilterProcessHandler.Run with a scripted pkt-line client.
// The client writes `clientScript` to the handler's stdin, then reads the
// handler's stdout into `serverOutput`. The handler's identity loader is
// short-circuited because none of these tests exercise actual reveal.
func runHandler(t *testing.T, clientScript []byte) []byte {
	t.Helper()

	handler := &FilterProcessHandler{
		Identities: nil,
	}

	var stdout bytes.Buffer
	err := handler.Run(t.Context(), bytes.NewReader(clientScript), &stdout)

	require.NoError(t, err)
	return stdout.Bytes()
}

// objectPathname is the per-blob `pathname=` header used by smudge tests
// that exercise framing only (no real reveal). The corresponding sesamDir
// becomes "." when the handler runs in chdirSesamRoot's tempdir.
const objectPathname = ".sesam/objects/test.sesam"

// chdirSesamRoot creates a temp dir with a `.sesam/` skeleton and chdirs into
// it for the lifetime of the test. The handler's per-blob spill file lands
// in `.sesam/tmp/`, so a writable .sesam tree is required even when reveal
// is expected to fail. Cleanup before reveal will warn (no git repo here),
// which is the same path real installations take when cleanup fails.
func chdirSesamRoot(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".sesam"), 0o700))
	cwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(cwd) })
}

// pktScript builds a pkt-line stream for use as test input. An empty payload
// emits a flush packet.
func pktScript(t *testing.T, payloads ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := pktline.NewEncoder(&buf)
	for _, p := range payloads {
		if p == "" {
			require.NoError(t, enc.Flush())
			continue
		}
		require.NoError(t, enc.EncodeString(p))
	}

	return buf.Bytes()
}

// readPkts decodes the handler's response into a slice of payloads. A flush
// packet appears as an empty string. Trailing newlines on payloads are
// preserved so that header/status framing can be asserted byte-for-byte.
func readPkts(t *testing.T, raw []byte) []string {
	t.Helper()
	scanner := pktline.NewScanner(bytes.NewReader(raw))
	var out []string
	for scanner.Scan() {
		out = append(out, string(scanner.Bytes()))
	}

	require.NoError(t, scanner.Err())
	return out
}

// validHandshake returns the pkt-lines a well-behaved client sends to open
// the conversation: greeting + capability offer.
func validHandshake(t *testing.T, capabilities ...string) []byte {
	t.Helper()
	parts := []string{"git-filter-client\n", "version=2\n", ""}
	for _, c := range capabilities {
		parts = append(parts, "capability="+c+"\n")
	}
	parts = append(parts, "")
	return pktScript(t, parts...)
}

func TestFilterProcessHandshake(t *testing.T) {
	script := validHandshake(t, "clean", "smudge")
	got := readPkts(t, runHandler(t, script))

	want := []string{
		"git-filter-server\n",
		"version=2\n",
		"",
		"capability=smudge\n",
		"",
	}

	require.Len(t, got, len(want))
	for i := range want {
		require.Equal(t, want[i], got[i], i)
	}
}

func TestFilterProcessOnlyAdvertisesSmudge(t *testing.T) {
	// Even when the client offers delay, we must not echo it back - sesam has
	// no async batching and advertising an unsupported capability would let
	// git assume we accept delayed responses.
	script := validHandshake(t, "clean", "smudge", "delay")
	got := readPkts(t, runHandler(t, script))

	for _, pkt := range got {
		if strings.HasPrefix(pkt, "capability=") && pkt != "capability=smudge\n" {
			require.Fail(t, "unexpected capability advertised: %q", pkt)
		}
	}
}

func TestFilterProcessClientWithoutSmudgeIsRejected(t *testing.T) {
	// A client that only offers `clean` cannot be served by sesam; surface
	// this as a hard error rather than silently accepting.
	script := validHandshake(t, "clean")
	handler := &FilterProcessHandler{Identities: nil}
	err := handler.Run(context.Background(), bytes.NewReader(script), io.Discard)

	require.ErrorIs(t, err, errProtocol)
}

func TestFilterProcessEOFAfterHandshake(t *testing.T) {
	// Closing stdin between requests is the normal end-of-session signal.
	script := validHandshake(t, "smudge")
	got := readPkts(t, runHandler(t, script))

	// Expect handshake response only; no per-blob frames.
	require.Len(t, got, 5)
}

func TestFilterProcessSmudgePassthrough(t *testing.T) {
	// A smudge with no identities: handler echoes the encrypted blob
	// unchanged and skips reveal. Asserts response framing.
	chdirSesamRoot(t)
	content := "encrypted-blob-bytes\n"

	script := bytes.Join([][]byte{
		validHandshake(t, "smudge"),
		pktScript(t,
			"command=smudge\n",
			"pathname="+objectPathname+"\n",
			"",
			content,
			"",
		),
	}, nil)

	out := readPkts(t, runHandler(t, script))

	// Skip handshake (5 packets), then expect: status=success, flush, content,
	// flush (end-of-content), flush (end-of-response).
	require.GreaterOrEqual(t, len(out), 5+5, "got packets %q", out)

	resp := out[5:]
	require.Equal(t, "status=success\n", resp[0])
	require.Equal(t, "", resp[1], "flush after status")
	require.Equal(t, content, resp[2], "echoed content")
	require.Equal(t, "", resp[3], "flush after content")
	require.Equal(t, "", resp[4], "final flush")
}

func TestFilterProcessEmptyContent(t *testing.T) {
	// Zero-byte blob: no content packets between header-flush and content-flush.
	// Response framing per protocol: status=success + flush, then a flush for
	// end-of-content (no content packets), then a final flush for end-of-response.
	chdirSesamRoot(t)
	script := bytes.Join([][]byte{
		validHandshake(t, "smudge"),
		pktScript(t,
			"command=smudge\n",
			"pathname="+objectPathname+"\n",
			"",
			"",
		),
	}, nil)

	out := readPkts(t, runHandler(t, script))
	resp := out[5:]

	want := []string{"status=success\n", "", "", ""}
	require.Equal(t, want, resp)
}

func TestFilterProcessLargeBlobIsRechunked(t *testing.T) {
	// Build content larger than MaxPayloadSize so the response must be split
	// across multiple pkt-lines. The client also sends it in one big logical
	// chunk by chaining several pkt-lines in the request.
	chdirSesamRoot(t)
	totalSize := pktline.MaxPayloadSize*2 + 1234
	full := strings.Repeat("y", totalSize)

	// Encode the request content in chunks of MaxPayloadSize.
	var content bytes.Buffer
	enc := pktline.NewEncoder(&content)
	remaining := full
	for len(remaining) > 0 {
		n := len(remaining)
		if n > pktline.MaxPayloadSize {
			n = pktline.MaxPayloadSize
		}
		require.NoError(t, enc.Encode([]byte(remaining[:n])))
		remaining = remaining[n:]
	}
	require.NoError(t, enc.Flush())

	script := bytes.Join([][]byte{
		validHandshake(t, "smudge"),
		pktScript(t,
			"command=smudge\n",
			"pathname="+objectPathname+"\n",
			"",
		),
		content.Bytes(),
	}, nil)

	out := readPkts(t, runHandler(t, script))
	resp := out[5:]

	// status=success, flush, then content packets, then end-of-content flush,
	// then end-of-response flush.
	require.Equal(t, "status=success\n", resp[0])
	require.Equal(t, "", resp[1], "flush after status")

	// Reassemble content packets up to the next flush.
	var got strings.Builder
	i := 2
	for i < len(resp) && resp[i] != "" {
		got.WriteString(resp[i])
		i++
	}
	require.Equal(t, full, got.String(), "content roundtrip")

	// Verify the chunking really happened (more than one content packet).
	contentPackets := i - 2
	require.GreaterOrEqualf(t, contentPackets, 2, "expected content split across multiple packets, got %d", contentPackets)
}

func TestFilterProcessUnknownCommandReturnsStatusError(t *testing.T) {
	// We only advertised `smudge`, so any other command is a protocol
	// violation. The handler tells git via status=error and bails - no
	// point draining a content stream we are about to abandon.
	script := bytes.Join([][]byte{
		validHandshake(t, "smudge"),
		pktScript(t,
			"command=clean\n",
			"pathname=outside/path.txt\n",
			"",
		),
	}, nil)

	handler := &FilterProcessHandler{Identities: nil}
	var stdout bytes.Buffer
	err := handler.Run(context.Background(), bytes.NewReader(script), &stdout)

	require.ErrorIs(t, err, errProtocol)
	resp := readPkts(t, stdout.Bytes())[5:]
	if len(resp) < 1 || resp[0] != "status=error\n" {
		require.Fail(t, "expected status=error response, got %q", resp)
	}
}
