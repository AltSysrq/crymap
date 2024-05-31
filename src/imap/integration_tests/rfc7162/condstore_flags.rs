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

use std::borrow::Cow;

use super::super::defs::*;
use crate::account::model::Flag;

#[test]
fn store_unchanged_since() {
    let setup = set_up();
    let mut client = setup.connect("7162cfsu");
    quick_log_in(&mut client);
    quick_create(&mut client, "7162cfsu");
    quick_append_enron(&mut client, "7162cfsu", 3);

    command!(mut responses = client, c("SELECT 7162cfsu (CONDSTORE)"));
    assert_tagged_ok_any(responses.pop().unwrap());
    let max_modseq = has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            code: Some(s::RespTextCode::HighestModseq(mm)),
            ..
        }) in responses => mm
    };

    // Update a couple messages. UNCHANGEDSINCE matches the modseq of one of
    // them.
    command!(mut responses = client,
             cb(&format!(
                 "STORE 1,3 (UNCHANGEDSINCE {}) +FLAGS.SILENT (\\seen)",
                 max_modseq)));
    assert_tagged_ok(responses.pop().unwrap());

    // Try to update one of the earlier ones again. This time, it should fail.
    // The server returns [MODIFIED] with the sequence number that couldn't be
    // changed, but the modification for message 2 still goes through since it
    // hasn't been touched yet.
    //
    // Additionally, the server provides us with the updated views of messages
    // 1 and 3.
    command!(mut responses = client, cb(&format!(
        "STORE 1:3 (UNCHANGEDSINCE {}) +FLAGS.SILENT (\\deleted)",
        max_modseq
    )));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Ok,
         Some(s::RespTextCode::Modified(ref modified)), _) =
            responses.pop().unwrap() =>
        {
            assert_eq!("1,3", modified);
        }
    };

    let new_modseq = has_untagged_response_matching! {
        s::Response::Fetch(ref fr @ s::FetchResponse {
            seqnum: 1,
            ..
        }) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Flags(..) in fr
            };

            has_msgatt_matching! {
                s::MsgAtt::Modseq(m) in fr => m
            }
        }
    };

    // Check that 1 really is unchanged and 2 really got \Deleted
    command!(responses = client, c("FETCH 1:2 FLAGS"));

    has_untagged_response_matching! {
        s::Response::Fetch(ref fr @ s::FetchResponse {
            seqnum: 1,
            ..
        }) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Flags(s::FlagsFetch::Recent(ref flags)) in fr => {
                    assert!(!flags.contains(&Flag::Deleted));
                }
            };
        }
    };
    has_untagged_response_matching! {
        s::Response::Fetch(ref fr @ s::FetchResponse {
            seqnum: 2,
            ..
        }) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Flags(s::FlagsFetch::Recent(ref flags)) in fr => {
                    assert!(flags.contains(&Flag::Deleted));
                }
            };
        }
    };

    // We can come back with the new modseq that the earlier unsolicited FETCH
    // gave us and actually update message 1.
    command!(mut responses = client, cb(&format!(
        "STORE 1 (UNCHANGEDSINCE {}) +FLAGS.SILENT (\\deleted)",
        new_modseq
    )));
    // Success = no response code
    assert_tagged_ok(responses.pop().unwrap());

    command!(responses = client, c("FETCH 1 FLAGS"));

    has_untagged_response_matching! {
        s::Response::Fetch(ref fr @ s::FetchResponse {
            seqnum: 1,
            ..
        }) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Flags(s::FlagsFetch::Recent(ref flags)) in fr => {
                    assert!(flags.contains(&Flag::Deleted));
                }
            };
        }
    };
}

#[test]
fn store_unchanged_concurrent() {
    let setup = set_up();
    let mut client = setup.connect("7162cfuc");
    quick_log_in(&mut client);
    quick_create(&mut client, "7162cfuc");
    quick_append_enron(&mut client, "7162cfuc", 2);

    command!(mut responses = client, c("SELECT 7162cfuc (CONDSTORE)"));
    assert_tagged_ok_any(responses.pop().unwrap());
    let max_modseq = has_untagged_response_matching! {
        s::Response::Cond(s::CondResponse {
            code: Some(s::RespTextCode::HighestModseq(mm)),
            ..
        }) in responses => mm
    };

    let mut client2 = setup.connect("7162cfuc2");
    quick_log_in(&mut client2);
    quick_select(&mut client2, "7162cfuc");
    ok_command!(client2, c("STORE 1 +FLAGS (\\seen)"));
    // The case where a message was expunged and then another client tries to
    // do a conditional STORE against it is a bit weird. The expungement
    // updates the message's modification modseq, which causes the STORE to
    // fail, but since we need to keep pretending that the expungement didn't
    // happen, the client gets the "updated" message anyway, and can then
    // proceed to try the flags update again and succeed.
    ok_command!(client2, c("XVANQUISH 2"));

    command!(mut responses = client, cb(&format!(
        "STORE 1:2 (UNCHANGEDSINCE {}) +FLAGS.SILENT (\\deleted)",
        max_modseq
    )));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Ok,
         Some(s::RespTextCode::Modified(ref modified)), _) =
            responses.pop().unwrap() =>
        {
            assert_eq!("1:2", modified);
        }
    };

    has_untagged_response_matching! {
        s::Response::Fetch(ref fr @ s::FetchResponse {
            seqnum: 1,
            ..
        }) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Flags(s::FlagsFetch::Recent(ref flags)) in fr => {
                    assert!(!flags.contains(&Flag::Deleted));
                }
            };
        }
    };
    let new_modseq = has_untagged_response_matching! {
        s::Response::Fetch(ref fr @ s::FetchResponse {
            seqnum: 2,
            ..
        }) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Flags(s::FlagsFetch::Recent(ref flags)) in fr => {
                    assert!(!flags.contains(&Flag::Deleted));
                }
            };

            has_msgatt_matching! {
                s::MsgAtt::Modseq(m) in fr => m
            }
        }
    };

    command!(mut responses = client, cb(&format!(
        "STORE 1:2 (UNCHANGEDSINCE {}) +FLAGS.SILENT (\\deleted)",
        new_modseq
    )));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Ok,
         Some(s::RespTextCode::Modified(Cow::Borrowed("1:2"))), _) =
            responses.pop().unwrap()
    };

    command!(responses = client, c("FETCH 1:2 FLAGS"));
    has_untagged_response_matching! {
        s::Response::Fetch(ref fr @ s::FetchResponse {
            seqnum: 1,
            ..
        }) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Flags(s::FlagsFetch::Recent(ref flags)) in fr => {
                    assert!(!flags.contains(&Flag::Deleted));
                }
            };
        }
    };
    has_untagged_response_matching! {
        s::Response::Fetch(ref fr @ s::FetchResponse {
            seqnum: 2,
            ..
        }) in responses => {
            has_msgatt_matching! {
                s::MsgAtt::Flags(s::FlagsFetch::Recent(ref flags)) in fr => {
                    assert!(!flags.contains(&Flag::Deleted));
                }
            }
        }
    };
}
