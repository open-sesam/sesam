package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli/v3"
)

func HandleStub(_ context.Context, _ *cli.Command) error {
	return fmt.Errorf("command %v is not implemented yet", strings.Join(os.Args[0:], " "))
}
