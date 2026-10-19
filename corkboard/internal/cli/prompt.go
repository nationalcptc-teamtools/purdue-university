package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"corkboard/internal/auth"
)

func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func readSecret(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	restore := func() {}
	if stdinIsTerminal() {
		if r, err := disableEcho(os.Stdin); err == nil {
			restore = r
		}
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	restore()
	if stdinIsTerminal() {
		fmt.Fprintln(os.Stderr)
	}
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func passphraseFrom(flagVal string, confirm bool) (string, error) {
	return passphraseWithEnv(flagVal, "CORK_PASSPHRASE", confirm)
}

func passphraseWithEnv(flagVal, envName string, confirm bool) (string, error) {
	p := flagVal
	if p == "" {
		p = os.Getenv(envName)
	}
	if p == "" {
		if !stdinIsTerminal() && confirm {
			return "", usageError("no passphrase: pass --passphrase, set $%s, or run in a terminal", envName)
		}
		label := "Team passphrase: "
		if confirm {
			label = fmt.Sprintf("New team passphrase (%d+ characters): ", auth.MinLen)
		}
		var err error
		if p, err = readSecret(label); err != nil {
			return "", err
		}
		if confirm {
			if err := auth.CheckPolicy(p); err != nil {
				return "", err
			}
			again, err := readSecret("Repeat it: ")
			if err != nil {
				return "", err
			}
			if again != p {
				return "", errors.New("the two passphrases don't match")
			}
		}
	}
	if confirm {
		if err := auth.CheckPolicy(p); err != nil {
			return "", err
		}
	}
	if p == "" {
		return "", errors.New("no passphrase given")
	}
	return p, nil
}
