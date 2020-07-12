//-
// Copyright (c) 2020, Jason Lingle
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

#![allow(dead_code)]

#[cfg(test)]
macro_rules! assert_matches {
    ($expected:pat, $actual:expr) => {
        match $actual {
            $expected => (),
            unexpected => panic!(
                "Expected {} matches {}, got {:?}",
                stringify!($expected),
                stringify!($actual),
                unexpected
            ),
        }
    };
}

mod account;
mod crypt;
mod imap;
mod mime;
mod support;

#[cfg(test)]
mod test_data;

fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
static INIT_TEST_LOG: std::sync::Once = std::sync::Once::new();

#[cfg(test)]
fn init_test_log() {
    INIT_TEST_LOG.call_once(|| {
        fern::Dispatch::new()
            .format(|out, message, record| {
                out.finish(format_args!(
                    "{} [{}][{}] {}",
                    chrono::Local::now().format("%H:%M:%S%.3f"),
                    record.level(),
                    record.target(),
                    message,
                ))
            })
            .level(log::LevelFilter::Debug)
            .chain(std::io::stderr())
            .apply()
            .unwrap();
    })
}
