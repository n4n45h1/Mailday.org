ALTER TABLE mailboxes ADD COLUMN encryption_mode TEXT NOT NULL DEFAULT 'standard';
ALTER TABLE mailboxes ADD COLUMN retention_seconds INTEGER NOT NULL DEFAULT 604800;
