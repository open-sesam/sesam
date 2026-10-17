package commands

import (
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

type runRequest struct {
	Path  string
	Args  []string
	Env   []string
	Files int
}

func runSupervised(ctx context.Context, request runRequest, files []*os.File, signals <-chan os.Signal) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case received := <-signals:
		return &ExitError{Signal: received.(syscall.Signal)}
	default:
	}

	executable, err := os.Executable()
	if err != nil {
		return err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()
	defer func() { _ = writer.Close() }()

	command := exec.Cmd{
		Path:       executable,
		Args:       []string{os.Args[0], "__run-supervisor"},
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		ExtraFiles: append([]*os.File{reader}, files...),
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start run supervisor: %w", err)
	}
	_ = reader.Close()
	// The pipe carries setup once, then stays open as the parent's liveness token.
	if err := gob.NewEncoder(writer).Encode(request); err != nil {
		_ = writer.Close()
		_ = command.Wait()
		return fmt.Errorf("configure run supervisor: %w", err)
	}
	return waitRunCommand(ctx, &command, signals, nil)
}

// RunSupervisor owns the immediate child and kills it if the outer sesam dies.
// Descriptor 3 is private control input; only secret descriptors reach the child.
func RunSupervisor() error {
	signals := runSignals()
	defer signal.Stop(signals)
	control := os.NewFile(3, "run-control")
	if control == nil {
		return fmt.Errorf("missing run supervisor control pipe")
	}
	defer func() { _ = control.Close() }()
	syscall.CloseOnExec(3)

	decoder := gob.NewDecoder(control)
	var request runRequest
	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("read run supervisor setup: %w", err)
	}
	if len(request.Args) == 0 || request.Path == "" || request.Files < 0 || request.Files > 256 {
		return fmt.Errorf("invalid run supervisor setup")
	}
	files := make([]*os.File, 0, request.Files)
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	for i := 0; i < request.Files; i++ {
		fd := 4 + i
		syscall.CloseOnExec(fd)
		files = append(files, os.NewFile(uintptr(fd), "run-secret"))
	}

	parentGone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, control)
		close(parentGone)
	}()
	command := exec.Cmd{
		Path:       request.Path,
		Args:       request.Args,
		Env:        request.Env,
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		ExtraFiles: files,
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("exec command %q: %w", request.Args[0], err)
	}
	return waitRunCommand(context.Background(), &command, signals, parentGone)
}

func runSignals() chan os.Signal {
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGTERM)
	return signals
}

func waitRunCommand(ctx context.Context, command *exec.Cmd, signals <-chan os.Signal, parentGone <-chan struct{}) error {
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	cancelled := ctx.Done()
	for {
		select {
		case err := <-done:
			return commandStatus(command.Args[0], err)
		case received := <-signals:
			_ = command.Process.Signal(received)
		case <-parentGone:
			_ = command.Process.Kill()
			parentGone = nil
		case <-cancelled:
			_ = command.Process.Signal(syscall.SIGTERM)
			cancelled = nil
		}
	}
}
