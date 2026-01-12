package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-maildir"
)

type Account struct {
	Address   string
	PassEntry string
	Host      string
	Port      int
}

type MailboxState struct {
	UIDValidity uint32 `json:"uid_validity"`
	LastUID     uint32 `json:"last_uid"`
}

type State struct {
	Mailboxes map[string]MailboxState `json:"mailboxes"`
}

type MailboxInfo struct {
	Name      string
	Delimiter string
}

func main() {
	var configPath string
	var rootMailDir string
	var inboxOnly bool
	var dryRun bool
	var skipNetC bool

	excluded := make(map[string]bool)
	flag.Func("exclude", "Mailbox name to exclude (can be repeated)", func(value string) error {
		excluded[value] = true
		return nil
	})

	flag.StringVar(&configPath, "config", "", "Config file path (defaults to $XDG_CONFIG_HOME/msk/misc/mail2)")
	flag.StringVar(&rootMailDir, "root", "", "Root maildir path (defaults to $XDG_DATA_HOME/mail)")
	flag.BoolVar(&inboxOnly, "inbox-only", false, "Only sync INBOX")
	flag.BoolVar(&dryRun, "dry-run", false, "List actions without writing maildir")
	flag.BoolVar(&skipNetC, "skip-net-c", true, "Skip net-c.com account")
	flag.Parse()

	if configPath == "" {
		xdgConfig := os.Getenv("XDG_CONFIG_HOME")
		if xdgConfig == "" {
			fatalf("XDG_CONFIG_HOME is not set; pass -config")
		}
		configPath = filepath.Join(xdgConfig, "msk", "misc", "mail2")
	}

	if rootMailDir == "" {
		xdgData := os.Getenv("XDG_DATA_HOME")
		if xdgData == "" {
			fatalf("XDG_DATA_HOME is not set; pass -root")
		}
		rootMailDir = filepath.Join(xdgData, "mail3")
	}

	if len(excluded) == 0 {
		excluded["[Gmail]/All Mail"] = true
	}

	accounts, err := loadAccounts(configPath)
	if err != nil {
		fatalf("load accounts: %v", err)
	}

	for _, acct := range accounts {
		if skipNetC && strings.Contains(acct.Address, "net-c.com") {
			logf("skip %s (net-c.com)", acct.Address)
			continue
		}
		if err := syncAccount(acct, rootMailDir, inboxOnly, dryRun, excluded); err != nil {
			logf("account %s: %v", acct.Address, err)
		}
	}
}

func loadAccounts(path string) ([]Account, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var accounts []Account
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return nil, fmt.Errorf("invalid account line: %q", line)
		}
		port, err := strconv.Atoi(fields[3])
		if err != nil {
			return nil, fmt.Errorf("invalid port in line: %q", line)
		}
		accounts = append(accounts, Account{
			Address:   fields[0],
			PassEntry: fields[1],
			Host:      fields[2],
			Port:      port,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return accounts, nil
}

func syncAccount(acct Account, rootMailDir string, inboxOnly, dryRun bool, excluded map[string]bool) error {
	pass, err := readPassword(acct.PassEntry)
	if err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", acct.Host, acct.Port)
	logf("connect %s", addr)

	tlsConfig := &tls.Config{ServerName: acct.Host}
	c, err := client.DialTLS(addr, tlsConfig)
	if err != nil {
		return err
	}
	defer c.Logout()

	if err := c.Login(acct.Address, pass); err != nil {
		return err
	}

	mailboxes, err := listMailboxes(c, inboxOnly, excluded)
	if err != nil {
		return err
	}

	acctRoot := filepath.Join(rootMailDir, acct.Address)
	if err := os.MkdirAll(acctRoot, 0o700); err != nil {
		return err
	}

	statePath := filepath.Join(acctRoot, ".mail3_state.json")
	state, err := loadState(statePath)
	if err != nil {
		return err
	}

	for _, mbox := range mailboxes {
		mboxPath := mailboxPath(acctRoot, mbox.Name, mbox.Delimiter)
		if err := syncMailbox(c, mbox.Name, mboxPath, dryRun, &state); err != nil {
			logf("%s/%s: %v", acct.Address, mbox.Name, err)
		}
	}

	if err := saveState(statePath, state); err != nil {
		return err
	}

	return nil
}

func listMailboxes(c *client.Client, inboxOnly bool, excluded map[string]bool) ([]MailboxInfo, error) {
	if inboxOnly {
		return []MailboxInfo{{Name: "INBOX", Delimiter: "/"}}, nil
	}

	mailboxes := make(chan *imap.MailboxInfo, 32)
	done := make(chan error, 1)
	var out []MailboxInfo

	go func() {
		for mbox := range mailboxes {
			if !canOpen(mbox) {
				continue
			}
			if excluded[mbox.Name] {
				continue
			}
			out = append(out, MailboxInfo{Name: mbox.Name, Delimiter: mbox.Delimiter})
		}
		done <- nil
	}()

	if err := c.List("", "*", mailboxes); err != nil {
		<-done
		return nil, err
	}
	<-done
	return out, nil
}

func canOpen(mbox *imap.MailboxInfo) bool {
	for _, attr := range mbox.Attributes {
		if attr == imap.NoSelectAttr || attr == "\\NonExistent" {
			return false
		}
	}
	return true
}

func syncMailbox(c *client.Client, name, path string, dryRun bool, state *State) error {
	logf("sync %s", name)
	mbox, err := c.Select(name, false)
	if err != nil {
		return err
	}

	mboxState := state.Mailboxes[name]
	if mbox.UidValidity != 0 && mboxState.UIDValidity != 0 && mboxState.UIDValidity != mbox.UidValidity {
		logf("uidvalidity changed for %s (was %d, now %d); resetting last uid", name, mboxState.UIDValidity, mbox.UidValidity)
		mboxState.LastUID = 0
	}
	mboxState.UIDValidity = mbox.UidValidity

	startUID := mboxState.LastUID + 1
	criteria := imap.NewSearchCriteria()
	criteria.Uid = new(imap.SeqSet)
	criteria.Uid.AddRange(startUID, 0)

	uids, err := c.UidSearch(criteria)
	if err != nil {
		return err
	}
	if len(uids) == 0 {
		state.Mailboxes[name] = mboxState
		return nil
	}

	if !dryRun {
		if err := maildir.Dir(path).Init(); err != nil {
			return err
		}
	}

	section := &imap.BodySectionName{}
	items := []imap.FetchItem{imap.FetchUid, imap.FetchFlags, section.FetchItem()}

	const batchSize = 50
	var maxUID uint32 = mboxState.LastUID
	for i := 0; i < len(uids); i += batchSize {
		end := i + batchSize
		if end > len(uids) {
			end = len(uids)
		}
		seqset := new(imap.SeqSet)
		seqset.AddNum(uids[i:end]...)

		messages := make(chan *imap.Message, batchSize)
		done := make(chan error, 1)
		go func() {
			done <- c.UidFetch(seqset, items, messages)
		}()

		for msg := range messages {
			if msg == nil {
				continue
			}
			if msg.Uid > maxUID {
				maxUID = msg.Uid
			}
			if dryRun {
				logf("%s: uid %d", name, msg.Uid)
				continue
			}
			reader := msg.GetBody(section)
			if reader == nil {
				return fmt.Errorf("uid %d: empty body", msg.Uid)
			}
			if err := writeMessage(path, reader, msg.Flags); err != nil {
				return fmt.Errorf("uid %d: %w", msg.Uid, err)
			}
		}

		if err := <-done; err != nil {
			return err
		}
	}

	mboxState.LastUID = maxUID
	state.Mailboxes[name] = mboxState
	return nil
}

func writeMessage(dir string, r io.Reader, imapFlags []string) error {
	dest := maildir.Dir(dir)
	flags := imapFlagsToMaildir(imapFlags)
	var writer io.WriteCloser
	if len(flags) == 0 {
		del, err := maildir.NewDelivery(dir)
		if err != nil {
			return err
		}
		writer = del
	} else {
		_, w, err := dest.Create(flags)
		if err != nil {
			return err
		}
		writer = w
	}
	defer writer.Close()
	if _, err := io.Copy(writer, r); err != nil {
		return err
	}
	return nil
}

func imapFlagsToMaildir(flags []string) []maildir.Flag {
	out := make([]maildir.Flag, 0, len(flags))
	for _, flag := range flags {
		switch flag {
		case imap.SeenFlag:
			out = append(out, maildir.FlagSeen)
		case imap.AnsweredFlag:
			out = append(out, maildir.FlagReplied)
		case imap.FlaggedFlag:
			out = append(out, maildir.FlagFlagged)
		case imap.DeletedFlag:
			out = append(out, maildir.FlagTrashed)
		case imap.DraftFlag:
			out = append(out, maildir.FlagDraft)
		}
	}
	return out
}

func mailboxPath(root, name, delim string) string {
	if name == "INBOX" {
		return filepath.Join(root, "INBOX")
	}
	if delim == "" {
		return filepath.Join(root, filepath.FromSlash(name))
	}
	parts := strings.Split(name, delim)
	return filepath.Join(append([]string{root}, parts...)...)
}

func loadState(path string) (State, error) {
	state := State{Mailboxes: make(map[string]MailboxState)}
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return state, nil
		}
		return state, err
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&state); err != nil {
		return state, err
	}
	if state.Mailboxes == nil {
		state.Mailboxes = make(map[string]MailboxState)
	}
	return state, nil
}

func saveState(path string, state State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp := fmt.Sprintf("%s.%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readPassword(entry string) (string, error) {
	cmd := exec.Command("msk_pass", "get", entry)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("msk_pass get %s: %w", entry, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func logf(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
