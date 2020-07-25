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

use super::super::defs::*;
use super::extract_highest_modseq;

#[test]
fn condstore_enable() {
    let setup = set_up();
    let mut client = setup.connect("7162cece");
    quick_log_in(&mut client);
    quick_create(&mut client, "7162cece");
    quick_append_enron(&mut client, "7162cece", 3);

    // Follows the order of "CONDSTORE enabling commands" from page 7 of RFC
    // 7162.
    assert_enabled_by(&setup, "SELECT 7162cece (CONDSTORE)");
    assert_enabled_by(&setup, "EXAMINE 7162cece (CONDSTORE)");
    assert_enabled_by(&setup, "STATUS INBOX (HIGHESTMODSEQ)");
    assert_enabled_by(&setup, "FETCH 1:* MODSEQ");
    assert_enabled_by(&setup, "SEARCH MODSEQ 0");
    assert_enabled_by(&setup, "FETCH 1:* UID (CHANGEDSINCE 0)");
    assert_enabled_by(
        &setup,
        "STORE 1:* (UNCHANGEDSINCE 0) \
                               -FLAGS.SILENT (keyword)",
    );
    assert_enabled_by(&setup, "ENABLE CONDSTORE");
}

fn assert_enabled_by(setup: &Setup, command: &'static str) {
    let mut client = setup.connect("7162cece");
    quick_log_in(&mut client);
    quick_select(&mut client, "7162cece");

    command!(responses = client, c(command));
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            code: Some(s::RespTextCode::HighestModseq(_)),
            ..
        }) in responses
    };

    command!(responses = client, c("EXAMINE 7162cece"));
    has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            code: Some(s::RespTextCode::HighestModseq(_)),
            ..
        }) in responses
    };
}

#[test]
fn enable_primordial() {
    let setup = set_up();
    let mut client = setup.connect("7162cesp");
    quick_log_in(&mut client);
    quick_create(&mut client, "7162cesp");
    quick_select(&mut client, "7162cesp");

    command!(mut responses = client, c("ENABLE CONDSTORE"));
    assert_tagged_ok_any(responses.pop().unwrap());
    assert_eq!(1, extract_highest_modseq(&responses));
}
