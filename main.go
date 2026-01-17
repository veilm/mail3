package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-maildir"
	"golang.org/x/net/html/charset"
)

type Config struct {
	Root     string          `json:"root"`
	Accounts []AccountConfig `json:"accounts"`
}

type AccountConfig struct {
	Name             string   `json:"name"`
	Address          string   `json:"address"`
	Username         string   `json:"username"`
	Host             string   `json:"host"`
	Port             int      `json:"port"`
	PasswordCommand  []string `json:"password_command"`
	Disabled         bool     `json:"disabled"`
	InboxOnly        bool     `json:"inbox_only"`
	ExcludeMailboxes []string `json:"exclude_mailboxes"`
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

type NewMessage struct {
	Account string
	Mailbox string
	UID     uint32
	Subject string
	From    string
}

var quiet bool
var trace bool

func main() {
	if len(os.Args) == 1 {
		printHelp()
		return
	}

	switch os.Args[1] {
	case "-h", "--help", "help":
		printHelp()
		return
	case "check":
		runCheck(os.Args[2:])
		return
	case "sync":
		runSync(os.Args[2:])
		return
	default:
		printHelp()
		os.Exit(2)
	}
}

func printHelp() {
	fmt.Println(`mail3 - minimal IMAP to Maildir puller

Usage:
  mail3 check [options]
  mail3 sync [options]
  mail3 --help

Check options:
  -config PATH        Path to config.json (default $XDG_CONFIG_HOME/mail3/config.json)
  -binary             Print 1 if any unread mail exists, otherwise 0
  -inbox-only         Only check INBOX for each account
  -account NAME       Only check a specific account (repeatable)

Sync options:
  -config PATH        Path to config.json (default $XDG_CONFIG_HOME/mail3/config.json)
  -root PATH          Override root maildir path
  -get-unread         Print only list of new unread mail; exit 1 if none
  -unique             Deduplicate unread output by account+from+subject
  -dry-run            List actions without writing maildir
  -account NAME       Only sync a specific account (repeatable)
`)
}

func runSync(args []string) {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	var configPath string
	var rootOverride string
	var listUnread bool
	var uniqueUnread bool
	var dryRun bool
	accountFilters := stringSlice{}
	fs.StringVar(&configPath, "config", "", "config path")
	fs.StringVar(&rootOverride, "root", "", "root maildir path override")
	fs.BoolVar(&listUnread, "get-unread", false, "print only list of new unread mail; exit 1 if none")
	fs.BoolVar(&uniqueUnread, "unique", false, "deduplicate unread output by account+from+subject")
	fs.BoolVar(&dryRun, "dry-run", false, "dry run")
	fs.BoolVar(&trace, "trace", false, "print timing per mailbox to stderr")
	fs.Var(&accountFilters, "account", "account name to sync (repeatable)")
	_ = fs.Parse(args)

	if listUnread {
		quiet = true
	}

	cfgPath := configPath
	if cfgPath == "" {
		xdgConfig := os.Getenv("XDG_CONFIG_HOME")
		if xdgConfig == "" {
			fatalf("XDG_CONFIG_HOME is not set; pass -config")
		}
		cfgPath = filepath.Join(xdgConfig, "mail3", "config.json")
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fatalf("load config: %v", err)
	}

	rootMailDir := cfg.Root
	if rootOverride != "" {
		rootMailDir = rootOverride
	}
	if rootMailDir == "" {
		xdgData := os.Getenv("XDG_DATA_HOME")
		if xdgData == "" {
			fatalf("XDG_DATA_HOME is not set; pass -root or set root in config")
		}
		rootMailDir = filepath.Join(xdgData, "mail3")
	}

	filters := make(map[string]bool)
	for _, name := range accountFilters {
		filters[name] = true
	}

	var unread []NewMessage
	startAll := time.Now()
	for _, acct := range cfg.Accounts {
		if acct.Disabled {
			logf("skip %s (disabled)", acct.Name)
			continue
		}
		if len(filters) > 0 && !filters[acct.Name] {
			continue
		}
		startAcct := time.Now()
		msgs, err := syncAccount(acct, rootMailDir, dryRun)
		if err != nil {
			logf("account %s: %v", acct.Name, err)
			continue
		}
		tracef("account %s: %s", acct.Name, time.Since(startAcct))
		unread = append(unread, msgs...)
	}
	tracef("total: %s", time.Since(startAll))

	if listUnread {
		if uniqueUnread {
			seen := make(map[string]bool, len(unread))
			unique := unread[:0]
			for _, msg := range unread {
				key := msg.Account + "\x00" + msg.From + "\x00" + msg.Subject
				if seen[key] {
					continue
				}
				seen[key] = true
				unique = append(unique, msg)
			}
			unread = unique
		}
		for _, msg := range unread {
			fmt.Printf("%s\t%s\t%v\t%s\t%s\n", msg.Account, msg.Mailbox, msg.UID, msg.From, msg.Subject)
		}
		if len(unread) == 0 {
			os.Exit(2)
		}
	}
}

func loadConfig(path string) (Config, error) {
	var cfg Config
	file, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func syncAccount(acct AccountConfig, rootMailDir string, dryRun bool) ([]NewMessage, error) {
	if acct.Address == "" || acct.Username == "" || acct.Host == "" || acct.Port == 0 {
		return nil, fmt.Errorf("account %s: missing required fields", acct.Name)
	}
	if len(acct.PasswordCommand) == 0 {
		return nil, fmt.Errorf("account %s: password_command is required", acct.Name)
	}

	pass, err := readPassword(acct.PasswordCommand)
	if err != nil {
		return nil, err
	}

	addr := fmt.Sprintf("%s:%d", acct.Host, acct.Port)
	logf("connect %s", addr)

	tlsConfig := &tls.Config{ServerName: acct.Host}
	c, err := client.DialTLS(addr, tlsConfig)
	if err != nil {
		return nil, err
	}
	defer c.Logout()

	if err := c.Login(acct.Username, pass); err != nil {
		return nil, err
	}

	excluded := make(map[string]bool)
	for _, name := range acct.ExcludeMailboxes {
		excluded[name] = true
	}

	mailboxes, err := listMailboxes(c, acct.InboxOnly, excluded)
	if err != nil {
		return nil, err
	}

	acctRoot := filepath.Join(rootMailDir, acct.Address)
	if err := os.MkdirAll(acctRoot, 0o700); err != nil {
		return nil, err
	}

	statePath := filepath.Join(acctRoot, ".mail3_state.json")
	state, err := loadState(statePath)
	if err != nil {
		return nil, err
	}

	var unread []NewMessage
	for _, mbox := range mailboxes {
		mboxPath := mailboxPath(acctRoot, mbox.Name, mbox.Delimiter)
		startMbox := time.Now()
		msgs, err := syncMailbox(c, mbox.Name, mboxPath, dryRun, &state)
		if err != nil {
			logf("%s/%s: %v", acct.Address, mbox.Name, err)
			continue
		}
		tracef("mailbox %s/%s: %s", acct.Name, mbox.Name, time.Since(startMbox))
		for _, msg := range msgs {
			msg.Account = acct.Name
			msg.Mailbox = mbox.Name
			unread = append(unread, msg)
		}
	}

	if err := saveState(statePath, state); err != nil {
		return nil, err
	}

	return unread, nil
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

func syncMailbox(c *client.Client, name, path string, dryRun bool, state *State) ([]NewMessage, error) {
	logf("sync %s", name)
	mbox, err := c.Select(name, false)
	if err != nil {
		return nil, err
	}
	tracef("mailbox %s: uidvalidity=%d uidnext=%d", name, mbox.UidValidity, mbox.UidNext)

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
		return nil, err
	}
	tracef("mailbox %s: last_uid=%d new=%d", name, mboxState.LastUID, len(uids))
	if len(uids) == 0 {
		state.Mailboxes[name] = mboxState
		return nil, nil
	}

	if !dryRun {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, err
		}
		if err := maildir.Dir(path).Init(); err != nil {
			return nil, err
		}
	}

	section := &imap.BodySectionName{Peek: true}
	items := []imap.FetchItem{imap.FetchUid, imap.FetchFlags, section.FetchItem()}

	const batchSize = 50
	var maxUID uint32 = mboxState.LastUID
	var unread []NewMessage
	var bytesFetched int64
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
				logf("%s: uid %d: empty body (skipping)", name, msg.Uid)
				continue
			}
			counter := &countingReader{r: reader}
			subject, from, err := writeMessage(path, counter, msg.Flags)
			if err != nil {
				return nil, fmt.Errorf("uid %d: %w", msg.Uid, err)
			}
			bytesFetched += counter.n
			if !hasSeen(msg.Flags) {
				unread = append(unread, NewMessage{UID: msg.Uid, Subject: subject, From: from})
			}
		}

		if err := <-done; err != nil {
			return nil, err
		}
	}

	mboxState.LastUID = maxUID
	state.Mailboxes[name] = mboxState
	tracef("mailbox %s: fetched_bytes=%d", name, bytesFetched)
	return unread, nil
}

func hasSeen(flags []string) bool {
	for _, flag := range flags {
		if flag == imap.SeenFlag {
			return true
		}
	}
	return false
}

func writeMessage(dir string, r io.Reader, imapFlags []string) (string, string, error) {
	dest := maildir.Dir(dir)
	flags := imapFlagsToMaildir(imapFlags)

	var writer io.WriteCloser
	if len(flags) == 0 {
		del, err := maildir.NewDelivery(dir)
		if err != nil {
			return "", "", err
		}
		writer = del
	} else {
		_, w, err := dest.Create(flags)
		if err != nil {
			return "", "", err
		}
		writer = w
	}
	defer writer.Close()

	br := bufio.NewReader(r)
	subject := ""
	from := ""
	lastHeader := ""

	for {
		line, err := br.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", "", err
		}
		if line == "\n" || line == "\r\n" || err != nil {
			if _, werr := io.WriteString(writer, line); werr != nil {
				return "", "", werr
			}
			if err == nil {
				if _, cerr := io.Copy(writer, br); cerr != nil {
					return "", "", cerr
				}
			}
			break
		}

		trimmed := strings.TrimRight(line, "\r\n")
		lower := strings.ToLower(strings.TrimSpace(trimmed))
		if strings.HasPrefix(lower, "subject:") && subject == "" {
			subject = strings.TrimSpace(trimmed[len("Subject:"):])
			lastHeader = "subject"
		} else if strings.HasPrefix(lower, "from:") && from == "" {
			from = strings.TrimSpace(trimmed[len("From:"):])
			lastHeader = "from"
		} else if (strings.HasPrefix(trimmed, " ") || strings.HasPrefix(trimmed, "\t")) && lastHeader != "" {
			continuation := strings.TrimSpace(trimmed)
			if lastHeader == "subject" && subject != "" {
				subject = subject + " " + continuation
			} else if lastHeader == "from" && from != "" {
				from = from + " " + continuation
			}
		} else {
			lastHeader = ""
		}

		if _, werr := io.WriteString(writer, line); werr != nil {
			return "", "", werr
		}

		if err != nil {
			break
		}
	}

	return decodeHeaderValue(subject), decodeHeaderValue(from), nil
}

func decodeHeaderValue(value string) string {
	if value == "" {
		return value
	}
	decoder := mime.WordDecoder{CharsetReader: charset.NewReaderLabel}
	decoded, err := decoder.DecodeHeader(value)
	if err != nil {
		return value
	}
	return decoded
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

func readPassword(command []string) (string, error) {
	cmd := exec.Command(command[0], command[1:]...)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("password command %q failed: %w", strings.Join(command, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func logf(format string, args ...any) {
	if quiet {
		return
	}
	fmt.Printf(format+"\n", args...)
}

func tracef(format string, args ...any) {
	if !trace {
		return
	}
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type UnseenResult struct {
	Account string
	Mailbox string
	Unseen  uint32
}

func runCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	var configPath string
	var binary bool
	var inboxOnly bool
	accountFilters := stringSlice{}
	fs.StringVar(&configPath, "config", "", "config path")
	fs.BoolVar(&binary, "binary", false, "print 1 if any unread mail exists, otherwise 0")
	fs.BoolVar(&inboxOnly, "inbox-only", false, "only check INBOX for each account")
	fs.Var(&accountFilters, "account", "account name to check (repeatable)")
	_ = fs.Parse(args)

	cfgPath := configPath
	if cfgPath == "" {
		xdgConfig := os.Getenv("XDG_CONFIG_HOME")
		if xdgConfig == "" {
			fatalf("XDG_CONFIG_HOME is not set; pass -config")
		}
		cfgPath = filepath.Join(xdgConfig, "mail3", "config.json")
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fatalf("load config: %v", err)
	}

	filters := make(map[string]bool)
	for _, name := range accountFilters {
		filters[name] = true
	}

	var results []UnseenResult
	var total uint32
	for _, acct := range cfg.Accounts {
		if acct.Disabled {
			continue
		}
		if len(filters) > 0 && !filters[acct.Name] {
			continue
		}
		if inboxOnly {
			acct.InboxOnly = true
		}
		unseen, err := checkAccount(acct)
		if err != nil {
			logf("account %s: %v", acct.Name, err)
			continue
		}
		for _, res := range unseen {
			if binary && res.Unseen > 0 {
				fmt.Println("1")
				return
			}
			results = append(results, res)
			total += res.Unseen
		}
	}

	if binary {
		fmt.Println("0")
		return
	}

	for _, res := range results {
		fmt.Printf("%s\t%s\t%d\n", res.Account, res.Mailbox, res.Unseen)
	}
	fmt.Printf("total\t%d\n", total)
}

func checkAccount(acct AccountConfig) ([]UnseenResult, error) {
	if acct.Address == "" || acct.Username == "" || acct.Host == "" || acct.Port == 0 {
		return nil, fmt.Errorf("account %s: missing required fields", acct.Name)
	}
	if len(acct.PasswordCommand) == 0 {
		return nil, fmt.Errorf("account %s: password_command is required", acct.Name)
	}

	pass, err := readPassword(acct.PasswordCommand)
	if err != nil {
		return nil, err
	}

	addr := fmt.Sprintf("%s:%d", acct.Host, acct.Port)
	tlsConfig := &tls.Config{ServerName: acct.Host}
	c, err := client.DialTLS(addr, tlsConfig)
	if err != nil {
		return nil, err
	}
	defer c.Logout()

	if err := c.Login(acct.Username, pass); err != nil {
		return nil, err
	}

	excluded := make(map[string]bool)
	for _, name := range acct.ExcludeMailboxes {
		excluded[name] = true
	}

	mailboxes, err := listMailboxes(c, acct.InboxOnly, excluded)
	if err != nil {
		return nil, err
	}

	var out []UnseenResult
	for _, mbox := range mailboxes {
		status, err := c.Status(mbox.Name, []imap.StatusItem{imap.StatusUnseen})
		if err != nil {
			return nil, err
		}
		if status.Unseen > 0 {
			out = append(out, UnseenResult{
				Account: acct.Name,
				Mailbox: mbox.Name,
				Unseen:  status.Unseen,
			})
		}
	}

	return out, nil
}
