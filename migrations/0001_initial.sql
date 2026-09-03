CREATE TABLE mailboxes (
  mailbox_id TEXT PRIMARY KEY,
  address TEXT NOT NULL UNIQUE,
  auth_public_key TEXT NOT NULL,
  encryption_public_key TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE messages (
  message_id TEXT PRIMARY KEY,
  mailbox_id TEXT NOT NULL,
  object_key TEXT NOT NULL UNIQUE,
  received_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  size INTEGER NOT NULL,
  FOREIGN KEY (mailbox_id) REFERENCES mailboxes(mailbox_id) ON DELETE CASCADE
);

CREATE INDEX messages_mailbox_received
  ON messages(mailbox_id, received_at DESC);
CREATE INDEX messages_expiry ON messages(expires_at);

CREATE TABLE challenges (
  challenge_id TEXT PRIMARY KEY,
  mailbox_id TEXT NOT NULL,
  challenge_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  FOREIGN KEY (mailbox_id) REFERENCES mailboxes(mailbox_id) ON DELETE CASCADE
);

CREATE INDEX challenges_expiry ON challenges(expires_at);

CREATE TABLE sessions (
  session_id TEXT PRIMARY KEY,
  mailbox_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  FOREIGN KEY (mailbox_id) REFERENCES mailboxes(mailbox_id) ON DELETE CASCADE
);

CREATE INDEX sessions_token ON sessions(token_hash);
CREATE INDEX sessions_expiry ON sessions(expires_at);
