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

-- Provides information about messages delivered to the user by not-logged-in
-- processes.
--
-- When a message is delivered externally, the message file is first written to
-- the key store, then an entry added to this table. This ensures that if the
-- second step fails, the message will at least eventually be recovered into
-- the inbox and allowing entries in `delivery` to be processed immediately
-- without needing to consider the possibility of the file not yet having been
-- written.
CREATE TABLE `delivery` (
  -- The path to the message relative to the message store.
  `path` TEXT NOT NULL,
  -- The path to the mailbox into which to deliver the message.
  --
  -- If such a delivery cannot be made, the message will instead be delivered
  -- into the inbox.
  `mailbox` TEXT NOT NULL,
  -- The initial flags to set on the message, separated by spaces. Invalid
  -- flags will be ignored.
  `flags` TEXT NOT NULL,
  -- The SAVEDATE value to set on the message when added to the destination
  -- mailbox.
  `savedate` INTEGER NOT NULL,
  -- If not NULL, some logged in process has attempted delivery of this entry.
  -- The entry is being kept around so that message recovery can see that the
  -- delivery is in-flight even if the file is not currently represented in the
  -- main database.
  --
  -- Delivery entries are dropped once this indicates they are too old, opening
  -- messages that were orphaned by failed delivery to orphan recovery.
  `delivered` INTEGER
) STRICT;

CREATE INDEX `delivery_path` ON `delivery` (`path`);
CREATE INDEX `delivery_delivered` ON `delivery` (`delivered`);
