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
mod cli;
mod crypt;
mod imap;
mod lmtp;
mod mime;
mod support;

#[cfg(test)]
mod test_data;

fn main() {
    cli::main::main();
}

#[cfg(test)]
static INIT_TEST_LOG: std::sync::Once = std::sync::Once::new();

#[cfg(test)]
fn init_test_log() {
    INIT_TEST_LOG.call_once(|| {
        if !std::env::var("TEST_LOG").ok().map_or(false, |v| "1" == v) {
            return;
        }

        init_simple_log();
    })
}

fn init_simple_log() {
    let stderr = log4rs::append::console::ConsoleAppender::builder()
        .target(log4rs::append::console::Target::Stderr)
        .encoder(Box::new(log4rs::encode::pattern::PatternEncoder::new(
            "{d(%H:%M:%S%.3f)} [{l}][{t}] {m}{n}",
        )))
        .build();
    let log_config = log4rs::config::Config::builder()
        .appender(
            log4rs::config::Appender::builder()
                .build("stderr", Box::new(stderr)),
        )
        .build(
            log4rs::config::Root::builder()
                .appender("stderr")
                .build(log::LevelFilter::Trace),
        )
        .unwrap();
    log4rs::init_config(log_config).unwrap();
}
