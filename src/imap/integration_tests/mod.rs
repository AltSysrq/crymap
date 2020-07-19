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

//! The integration tests are near "full-stack" tests which run the actual
//! client and server code, without test-specific modifications and with as
//! little "reaching under the covers" as possible.
//!
//! Since initialising an account, particularly with the default RSA settings,
//! is a somewhat slow process, the tests will share a single system directory
//! and account as long as they are run concurrently. (The system directory is
//! removed as soon as no test using it is running to ensure that it does in
//! fact get cleaned up in all cases.)
//!
//! Each "connection" spawns a dedicated server thread. The client communicates
//! to the server over a pair of UNIX pipes (as in `pipe(2)`), which presents a
//! reasonable approximation of a real network connection without the tests
//! needing to worry about port numbers and such.
//!
//! Since the tests run within one account, they typically create their own
//! mailbox or mailbox hierarchy, each named after the test in question.

macro_rules! command {
    ($responses:ident = $client:expr, $command:expr) => {
        let mut buffer = Vec::new();
        let $responses = $client.command($command, &mut buffer).unwrap();
    };
    (mut $responses:ident = $client:expr, $command:expr) => {
        let mut buffer = Vec::new();
        let mut $responses = $client.command($command, &mut buffer).unwrap();
    };
    ([$response:ident] = $client:expr, $command:expr) => {
        command!(responses = $client, $command);
        assert_eq!(1, responses.len());
        let $response = responses.into_iter().next().unwrap();
    };
}

macro_rules! ok_command {
    ($client:ident, $command:expr) => {{
        let mut buffer = Vec::new();
        let mut responses = $client.command($command, &mut buffer).unwrap();
        assert!(responses.len() >= 1);
        assert_tagged_ok_any(responses.pop().unwrap());
    }};
}

macro_rules! unpack_cond_response {
    (($tag:pat, $cond:pat, $code:pat, $quip:pat) = $resp:expr) => {
        unpack_cond_response! {
            ($tag, $cond, $code, $quip) = $resp => ()
        }
    };

    (($tag:pat, $cond:pat, $code:pat, $quip:pat) = $resp:expr
     => $body:expr) => {
        match $resp {
            s::ResponseLine {
                tag: $tag,
                response:
                    s::Response::Cond(s::CondResponse {
                        cond: $cond,
                        code: $code,
                        quip: $quip,
                    }),
            } => $body,
            r => panic!("Unexpected response: {:?}", r),
        }
    };
}

macro_rules! has_untagged_response_matching {
    ($pat:pat in $responses:expr) => {
        has_untagged_response_matching! {
            $pat in $responses => ()
        }
    };
    ($pat:pat in $responses:expr => $result:expr) => {{
        $responses
            .iter()
            .filter_map(|response| match *response {
                s::ResponseLine {
                    tag: None,
                    response: $pat,
                } => Some($result),

                _ => None,
            })
            .next()
            .expect("Expected response not found")
    }};
}

macro_rules! has_msgatt_matching {
    (move $pat:pat in $fetch_response:expr) => {
        has_msgatt_matching! {
            move $pat in $fetch_response => ()
        }
    };

    (move $pat:pat in $fetch_response:expr => $result:expr) => {
        $fetch_response
            .atts
            .atts
            .into_iter()
            .filter_map(|msgatt| match msgatt {
                $pat => Some($result),
                _ => None,
            })
            .next()
            .expect("Expected FETCH attribute not found")
    };

    ($pat:pat in $fetch_response:expr) => {
        has_msgatt_matching! {
            $pat in $fetch_response => ()
        }
    };

    ($pat:pat in $fetch_response:expr => $result:expr) => {
        $fetch_response
            .atts
            .atts
            .iter()
            .filter_map(|msgatt| match *msgatt {
                $pat => Some($result),
                _ => None,
            })
            .next()
            .expect("Expected FETCH attribute not found")
    };
}

mod defs;

mod rfc3501;
mod rfc3502;
mod rfc4315;
mod rfc7888;
