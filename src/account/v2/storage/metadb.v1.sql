---
-- Copyright (c) 2023, Jason Lingle
--
-- This file is part of Crymap.
--
-- Crymap is free software: you can  redistribute it and/or modify it under the
-- terms of  the GNU General Public  License as published by  the Free Software
-- Foundation, either version  3 of the License, or (at  your option) any later
-- version.
--
-- Crymap is distributed  in the hope that  it will be useful,  but WITHOUT ANY
-- WARRANTY; without  even the implied  warranty of MERCHANTABILITY  or FITNESS
-- FOR  A PARTICULAR  PURPOSE.  See the  GNU General  Public  License for  more
-- details.
--
-- You should have received a copy of the GNU General Public License along with
-- Crymap. If not, see <http://www.gnu.org/licenses/>.

-- Defines the mailboxes owned by the user.
--
-- The hierarchy is not explicitly represented and must be inferred from the
-- paths.
CREATE TABLE `mailbox` (
  -- The surrogate ID for this mailbox. This is also used for the MAILBOXID
  -- reported to the client and is also the `UIDVALIDITY` value.
  -- (`AUTOINCREMENT` starts at 1, so we don't end up with a `UIDVALIDITY` of
  -- 0.)
  `id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  -- The parent of this mailbox, or NULL if this is under the root.
  `parent_id` INTEGER NOT NULL,
  -- The IMAP name for this mailbox. E.g. "INBOX"; "TPS Reports".
  `name` TEXT NOT NULL,
  -- Whether this mailbox is selectable. An unselectable mailbox is brought
  -- about by `DELETE`ing a mailbox which has children.
  `selectable` INTEGER NOT NULL DEFAULT TRUE,
  -- If this is a special-use mailbox, the special use attribute (e.g.
  -- "\Sent").
  `special_use` TEXT,
  -- The next UID to provision for a message.
  `next_uid` INTEGER NOT NULL DEFAULT 1,
  -- The UID of the first message to mark as "recent".
  `recent_uid` INTEGER NOT NULL DEFAULT 1,
  -- The latest modification sequence number that has been used in this
  -- mailbox. Modseq 1 is the initial state of the mailbox.
  `max_modseq` INTEGER NOT NULL DEFAULT 1,
  UNIQUE (`parent_id`, `name`),
  FOREIGN KEY (`parent_id`) REFERENCES `mailbox` (`id`) ON DELETE RESTRICT
) STRICT;

-- Pre-seed the special root pseudo-mailbox.
INSERT INTO `mailbox` (`id`, `parent_id`, `name`, `selectable`)
VALUES (0, 0, '/', false);

-- Defines the known flags for an account.
--
-- The set of extant flags is global across the whole account. This ensures
-- that the flag table of a message doesn't need to be rewritten when it is
-- moved to another mailbox and eliminates separate bookkeeping about which
-- flags exist for each specific mailbox.
CREATE TABLE `flag` (
  -- The integer ID for this flag.
  --
  -- In messages, this is the offset + 1 of the bit corresponding to the flag
  -- (because AUTOINCREMENT starts at 1).
  `id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  -- The flag itself. E.g. "\Deleted", "\Sent", "Keyword".
  --
  -- Flags are ASCII-only so the built-in NOCASE collation is sufficient.
  `flag` TEXT COLLATE NOCASE NOT NULL,
  UNIQUE (`flag`)
) STRICT;

-- Pre-seed the database with the non-keyword flags. This ensures they have low
-- IDs and also addresses the fact that AUTOINCREMENT starts at 1; this way, we
-- can ensure bit 0 is used too without needing to do offsetting in code.
INSERT INTO `flag` (`id`, `flag`) VALUES
  -- We specifically make \Seen be bit 0 since the most common flag combination
  -- is simply \Seen (i.e. just \Seen is 1) and SQLite has a compact
  -- representation for integers 0 and 1.
  (0, '\Seen'),
  (1, '\Answered'),
  (2, '\Deleted'),
  (3, '\Draft'),
  (4, '\Flagged');

-- Tracks all messages which exist in the user's account.
--
-- Messages are not inherently associated with any mailbox, but are brought in
-- via `mailbox_message`. `COPY` and so forth merely add more references to the
-- same message.
CREATE TABLE `message` (
  -- The surrogate ID for this message. This is also used for the EMAILID
  -- return to the client.
  `id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  -- The file path of this message relative to the root of the message store.
  --
  -- This is usually a hex SHA-3 hash with a `/` after the first octet, but we
  -- support arbitrary paths to simplify file recovery (i.e. an admin can just
  -- drop a file in with an arbitrary path).
  `path` TEXT NOT NULL,
  -- The 16-byte session key used to encrypt the message, if known. The session
  -- key is XOR'ed with a 16-bit KMAC derived from the master key unique to
  -- `path` so that breaking the weaker XEX encryption of the database does not
  -- compromise the session keys.
  `session_key` BLOB,
  -- The value of `RFC822.SIZE`, if known.
  `rfc822_size` INTEGER,
  -- The last time (as a UNIX timestamp, seconds) at which the message was
  -- expunged from any mailbox or had other activity that could result in it
  -- being orphaned.
  --
  -- This is used to identify when it is safe to delete orphaned messages.
  `last_activity` INTEGER NOT NULL,
  UNIQUE (`path`)
) STRICT;

-- An instance of a message within a mailbox.
CREATE TABLE `mailbox_message` (
  -- The mailbox that contains the message.
  `mailbox_id` INTEGER NOT NULL,
  -- The UID of this instance within the mailbox.
  `uid` INTEGER NOT NULL,
  -- The message itself.
  `message_id` INTEGER NOT NULL,
  -- The first 64 flags as a bitset.
  `near_flags` INTEGER NOT NULL,
  -- The datetime (UNIX, seconds) at which this instance of the message was
  -- appended.
  `savedate` INTEGER NOT NULL,
  -- The modseq at which this instance of the message was appended.
  `append_modseq` INTEGER NOT NULL,
  -- The modseq at which the flags were changed.
  `flags_modseq` INTEGER NOT NULL,
  PRIMARY KEY (`mailbox_id`, `uid`),
  FOREIGN KEY (`mailbox_id`) REFERENCES `mailbox` (`id`) ON DELETE RESTRICT,
  FOREIGN KEY (`message_id`) REFERENCES `message` (`id`) ON DELETE RESTRICT
) WITHOUT ROWID, STRICT;

-- Associates flags with indices >63 with messages.
CREATE TABLE `mailbox_message_far_flag` (
  `mailbox_id` INTEGER NOT NULL,
  `uid` INTEGER NOT NULL,
  `flag_id` INTEGER NOT NULL,
  PRIMARY KEY (`mailbox_id`, `uid`, `flag_id`),
  FOREIGN KEY (`mailbox_id`, `uid`)
    REFERENCES `mailbox_message` (`mailbox_id`, `uid`) ON DELETE RESTRICT,
  FOREIGN KEY (`flag_id`) REFERENCES `flag` (`id`) ON DELETE RESTRICT
) WITHOUT ROWID, STRICT;

CREATE TABLE `mailbox_message_expungement` (
  `mailbox_id` INTEGER NOT NULL,
  `uid` INTEGER NOT NULL,
  `expunged_modseq` INTEGER NOT NULL,
  -- This primary key + WITHOUT ROWID means that it is extremely efficient to
  -- scan in everything that changed after a certain point within one mailbox,
  -- as such a query will be a binary search then a linear table scan to gather
  -- all the UIDs.
  PRIMARY KEY (`mailbox_id`, `expunged_modseq`, `uid`),
  FOREIGN KEY (`mailbox_id`) REFERENCES `mailbox` (`id`) ON DELETE RESTRICT
) WITHOUT ROWID, STRICT;

-- Tracks the set of subscribed mailbox paths.
CREATE TABLE `subscription` (
  `path` TEXT NOT NULL PRIMARY KEY
) STRICT;

-- Used to coordinate periodic maintenance operations.
CREATE TABLE `maintenance` (
  -- The type of maintenance in question.
  `name` TEXT NOT NULL PRIMARY KEY,
  -- The datetime (UNIX, seconds) at which a process last started this kind of
  -- maintenance.
  `last_started` INTEGER NOT NULL
) STRICT;
