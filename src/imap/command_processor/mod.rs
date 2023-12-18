//-
// Copyright (c) 2020, 2023, Jason Lingle
//
// This file is part of Crymap.
//
// Crymap is free software: you can  redistribute it and/or modify it under the
// terms of  the GNU General Public  License as published by  the Free Software
// Foundation, either version  3 of the License, or (at  your option) any later
// version.
//
// Crymap is distributed  in the hope that  it will be useful,  but WITHOUT ANY
// WARRANTY; without  even the implied  warranty of MERCHANTABILITY  or FITNESS
// FOR  A PARTICULAR  PURPOSE.  See the  GNU General  Public  License for  more
// details.
//
// You should have received a copy of the GNU General Public License along with
// Crymap. If not, see <http://www.gnu.org/licenses/>.

//! Implements most of the IMAP protocol, specifically that which is not
//! sensitive to the actual wire format.
//!
//! As with `account::v2::state`, this module is split into several submodules
//! for manageability, but is best thought of as one single module.

macro_rules! map_error {
    ($this:expr) => {{
        let log_prefix = &$this.log_prefix;
        let account = $this.account.as_mut();
        let selected = $this.selected.as_ref();
        move |e| {
            let selected_ok = account.map_or(
                true, |account| selected.map_or(
                    true, |s| account.is_usable_mailbox(s)));
            catch_all_error_handling(selected_ok, log_prefix, e)
        }
    }};

    ($this:expr, $($($kind:ident)|+ => ($cond:ident, $code:expr),)+) => {{
        let log_prefix = &$this.log_prefix;
        let account = $this.account.as_mut();
        let selected = $this.selected.as_ref();
        move |e| match e {
            $($(Error::$kind)|* => s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::$cond,
                code: $code,
                quip: Some(Cow::Owned(e.to_string())),
            }),)*
            e => {
                let selected_ok = account.map_or(
                    true, |account| selected.map_or(
                        true, |s| account.is_usable_mailbox(s)));
                catch_all_error_handling(selected_ok, log_prefix, e)
            }
        }
    }};
}

// account! and selected! are macros instead of methods on CommandProcessor
// since there is no way to express that they borrow only one field --- as a
// method, the returned value is considered to borrow the whole
// `CommandProcessor`.
macro_rules! account {
    ($this:expr) => {
        $this.account.as_mut().ok_or_else(|| {
            s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Bad,
                code: None,
                quip: Some(Cow::Borrowed("Not logged in")),
            })
        })
    };
}

macro_rules! selected {
    ($this:expr) => {
        $this.selected.as_mut().ok_or_else(|| {
            s::Response::Cond(s::CondResponse {
                cond: s::RespCondType::Bad,
                code: None,
                quip: Some(Cow::Borrowed("No mailbox selected")),
            })
        })
    };
}

mod auth;
mod commands;
mod defs;
mod fetch;
mod flags;
mod mailboxes;
mod messages;
mod search;
mod user_config;

pub use self::defs::CommandProcessor;
