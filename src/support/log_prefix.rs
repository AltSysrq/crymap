//-
// Copyright (c) 2023, 2024, Jason Lingle
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

use std::fmt;
use std::mem;
use std::sync::{Arc, Mutex};

/// Tracks text that should be included in at the start of every log statement.
///
/// Clones of a `LogPrefix` share the same underlying data.
#[derive(Clone)]
pub struct LogPrefix {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Clone)]
struct Inner {
    protocol: String,
    user: Option<String>,
    helo: Option<String>,
    ua_name: Option<String>,
    ua_version: Option<String>,
}

impl LogPrefix {
    pub fn new(protocol: String) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                protocol,
                user: None,
                helo: None,
                ua_name: None,
                ua_version: None,
            })),
        }
    }

    pub fn deep_clone(&self) -> Self {
        let inner = self.inner.lock().unwrap();
        Self {
            inner: Arc::new(Mutex::new(Inner::clone(&inner))),
        }
    }

    pub fn set_user(&self, user: String) {
        self.inner.lock().unwrap().user = Some(sanitise(user));
    }

    pub fn set_helo(&self, helo: String) {
        self.inner.lock().unwrap().helo = Some(sanitise(helo));
    }

    pub fn set_user_agent(
        &self,
        name: Option<String>,
        version: Option<String>,
    ) {
        let mut inner = self.inner.lock().unwrap();
        inner.ua_name = name.map(sanitise);
        inner.ua_version = version.map(sanitise);
    }
}

impl fmt::Display for LogPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let inner = self.inner.lock().unwrap();
        write!(f, "{}", inner.protocol)?;
        if inner.user.is_some()
            || inner.helo.is_some()
            || inner.ua_name.is_some()
            || inner.ua_version.is_some()
        {
            write!(f, "[")?;
            let mut first = true;
            if let Some(ref user) = inner.user {
                write!(f, "{user}")?;
                first = false;
            }

            if let Some(ref helo) = inner.helo {
                if !mem::take(&mut first) {
                    write!(f, " ")?;
                }
                write!(f, "helo={helo}")?;
            }

            if inner.ua_name.is_some() || inner.ua_version.is_some() {
                if !mem::take(&mut first) {
                    write!(f, " ")?;
                }
                write!(
                    f,
                    "agent={}/{}",
                    inner.ua_name.as_deref().unwrap_or("unknown"),
                    inner.ua_version.as_deref().unwrap_or("unknown"),
                )?;
            }
            write!(f, "]")?;
        }

        Ok(())
    }
}

fn sanitise(mut s: String) -> String {
    s.retain(|c| !c.is_control());
    if let Some((truncate_len, _)) = s.char_indices().nth(64) {
        s.truncate(truncate_len);
    }

    s
}
