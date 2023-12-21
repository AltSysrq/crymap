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

use chrono::prelude::*;

use super::defs::*;

#[test]
fn capability_declared() {
    test_require_capability("8514capa", "SAVEDATE");
}

#[test]
fn fetch() {
    let setup = set_up();
    let mut client = setup.connect("8514ftch");
    quick_log_in(&mut client);
    quick_create(&mut client, "8514ftch");
    quick_select(&mut client, "8514ftch");
    quick_append_enron(&mut client, "8514ftch", 1);

    fetch_single!(client, c("FETCH 1 SAVEDATE"), ref fr => {
        has_msgatt_matching! {
            s::MsgAtt::SaveDate(Some(_)) in fr
        };
    });
}

#[test]
fn search() {
    let setup = set_up();
    let mut client = setup.connect("8514srch");
    quick_log_in(&mut client);
    quick_create(&mut client, "8514srch");
    quick_select(&mut client, "8514srch");
    quick_append_enron(&mut client, "8514srch", 1);

    let today = Utc::now().date_naive();
    let yesterday = today
        .checked_sub_days(chrono::Days::new(1))
        .unwrap()
        .format("%d-%b-%Y")
        .to_string();
    let tomorrow = today
        .checked_add_days(chrono::Days::new(1))
        .unwrap()
        .format("%d-%b-%Y")
        .to_string();
    let today = today.format("%d-%b-%Y").to_string();

    let mut check = |expect: bool, s: &str| {
        command!(mut responses = client, cb(s));
        assert_eq!(2, responses.len());
        assert_tagged_ok(responses.pop().unwrap());

        let hits = match responses.pop().unwrap() {
            s::ResponseLine {
                tag: None,
                response: s::Response::Search(v),
            } => v.hits,
            r => panic!("Unexpected response: {:?}", r),
        };

        assert_eq!(expect, !hits.is_empty());
    };

    check(false, &format!("UID SEARCH SAVEDON {yesterday}"));
    check(true, &format!("UID SEARCH SAVEDON {today}"));
    check(false, &format!("UID SEARCH SAVEDON {tomorrow}"));

    check(false, &format!("UID SEARCH SAVEDBEFORE {yesterday}"));
    check(false, &format!("UID SEARCH SAVEDBEFORE {today}"));
    check(true, &format!("UID SEARCH SAVEDBEFORE {tomorrow}"));

    check(true, &format!("UID SEARCH SAVEDSINCE {yesterday}"));
    check(false, &format!("UID SEARCH SAVEDSINCE {today}"));
    check(false, &format!("UID SEARCH SAVEDSINCE {tomorrow}"));
}
