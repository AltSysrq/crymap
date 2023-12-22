//-
// Copyright (c) 2023, Jason Lingle
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
    ua_name: Option<String>,
    ua_version: Option<String>,
}

impl LogPrefix {
    pub fn new(protocol: String) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                protocol,
                user: None,
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
        self.inner.lock().unwrap().user = Some(user.to_owned());
    }

    pub fn set_user_agent(
        &self,
        name: Option<String>,
        version: Option<String>,
    ) {
        let mut inner = self.inner.lock().unwrap();
        inner.ua_name = name;
        inner.ua_version = version;
    }
}

impl fmt::Display for LogPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let inner = self.inner.lock().unwrap();
        write!(f, "{}", inner.protocol)?;
        if inner.user.is_some()
            || inner.ua_name.is_some()
            || inner.ua_version.is_some()
        {
            write!(f, "[{}", inner.user.as_deref().unwrap_or("<anon>"))?;

            if inner.ua_name.is_some() || inner.ua_version.is_some() {
                write!(
                    f,
                    " {}/{}",
                    inner.ua_name.as_deref().unwrap_or("unknown"),
                    inner.ua_version.as_deref().unwrap_or("unknown"),
                )?;
            }
            write!(f, "]")?;
        }

        Ok(())
    }
}
