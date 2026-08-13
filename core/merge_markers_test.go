package core

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHasConflictMarkers(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{
			name: "real conflict",
			in:   "a\n<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> other\nb\n",
			want: true,
		},
		{
			name: "diff3 conflict (base section) still has start+end",
			in:   "<<<<<<< ours\nx\n||||||| base\ny\n=======\nz\n>>>>>>> theirs\n",
			want: true,
		},
		{
			name: "label-less markers",
			in:   "<<<<<<<\nours\n=======\ntheirs\n>>>>>>>\n",
			want: true,
		},
		{
			name: "lone separator is not a conflict",
			in:   "title\n=======\nunderline-style heading\n",
			want: false,
		},
		{
			name: "start without end is not flagged",
			in:   "<<<<<<< looks like a start but no end marker\ndata\n",
			want: false,
		},
		{
			name: "short runs are not markers",
			in:   "<<<< four\n>>>> four\n",
			want: false,
		},
		{
			name: "markers must be at line start",
			in:   "prefix <<<<<<< HEAD\nprefix >>>>>>> other\n",
			want: false,
		},
		{
			name: "clean file",
			in:   "user = admin\npassword = hunter2\n",
			want: false,
		},
		{
			name: "empty file",
			in:   "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hasConflictMarkers(strings.NewReader(tt.in))
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
