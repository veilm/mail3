# mail3

Minimal IMAP-to-Maildir puller using go-imap (same IMAP library aerc uses).

## Usage

- `mail3 --help`
- `mail3 sync`
- `mail3 sync -list-unread`
- `mail3 sync -account 1411 -account ms2`

By default, config is read from `$XDG_CONFIG_HOME/mail3/config.json` and mail is stored under `$XDG_DATA_HOME/mail3`.

## Config format

`config.json` example:

```json
{
  "root": "/home/user/.local/share/mail3",
  "accounts": [
    {
      "name": "personal",
      "address": "user@example.com",
      "username": "user@example.com",
      "host": "imap.example.com",
      "port": 993,
      "password_command": ["pass", "show", "mail/example.com"],
      "exclude_mailboxes": ["[Gmail]/All Mail"]
    },
    {
      "name": "work",
      "address": "user@corp.example",
      "username": "user@corp.example",
      "host": "imap.corp.example",
      "port": 993,
      "password_command": ["secret-tool", "lookup", "service", "imap", "user", "user@corp.example"],
      "disabled": true
    }
  ]
}
```

Fields:
- `root` (optional): override the local mail root directory. If omitted, defaults to `$XDG_DATA_HOME/mail3`.
- `accounts` (required): list of account objects.
- `name` (required): short identifier used by `-account` and unread output.
- `address` (required): used as the local maildir root for the account.
- `username` (required): IMAP login username.
- `host` (required): IMAP server host.
- `port` (required): IMAP server port.
- `password_command` (required): command (argv array) that prints the password on stdout.
- `disabled` (optional): skip syncing this account when true.
- `inbox_only` (optional): only sync INBOX when true.
- `exclude_mailboxes` (optional): list of mailbox names to skip.

## Notes

- Pull-only: this does not push changes back to the server.
- New/unread listing uses the IMAP \Seen flag and only reports messages fetched in the current run.
