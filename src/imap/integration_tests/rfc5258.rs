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

use super::defs::*;

#[test]
fn capability_declared() {
    test_require_capability("5258capa", "LIST-EXTENDED");
}

#[test]
fn return_options_honoured() {
    let setup = set_up();
    let mut client = setup.connect("5258retn");
    quick_log_in(&mut client);
    quick_create(&mut client, "5258retn/subscribed");
    quick_create(&mut client, "5258retn/parent/child");
    quick_create(&mut client, "5258retn/single");
    ok_command!(client, c("SUBSCRIBE 5258retn/subscribed"));

    // Syntax by sending a list of one pattern counts as using extended syntax.
    command!(mut responses = client, c("LIST \"\" (5258retn/%)"));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        "5258retn/parent\n\
         5258retn/single\n\
         5258retn/subscribed\n",
        list_results_to_str(responses)
    );

    command!(mut responses = client, c("LIST \"\" 5258retn/% RETURN ()"));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        "5258retn/parent\n\
         5258retn/single\n\
         5258retn/subscribed\n",
        list_results_to_str(responses)
    );

    command!(mut responses = client,
             c("LIST \"\" 5258retn/% RETURN (CHILDREN)"));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        "5258retn/parent \\HasChildren\n\
         5258retn/single \\HasNoChildren\n\
         5258retn/subscribed \\HasNoChildren\n",
        list_results_to_str(responses)
    );

    command!(mut responses = client,
             c("LIST \"\" 5258retn/% RETURN (SUBSCRIBED)"));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        "5258retn/parent\n\
         5258retn/single\n\
         5258retn/subscribed \\Subscribed\n",
        list_results_to_str(responses)
    );

    command!(mut responses = client,
             c("LIST \"\" 5258retn/% RETURN (CHILDREN SUBSCRIBED)"));
    assert_tagged_ok(responses.pop().unwrap());
    assert_eq!(
        "5258retn/parent \\HasChildren\n\
         5258retn/single \\HasNoChildren\n\
         5258retn/subscribed \\HasNoChildren \\Subscribed\n",
        list_results_to_str(responses)
    );

    command!([response] = client, c("LIST (RECURSIVEMATCH) \"\" *"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, None, _) = response
    };

    client
        .write_raw(b"LIST \"\" 5258retn/% RETURN (CHILDREN XYZZY)\r\n")
        .unwrap();
    let mut buffer = Vec::new();
    let response = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad,
         Some(s::RespTextCode::Parse(())), _) = response
    };
}

#[test]
fn rfc_examples() {
    // Refer to the `list_extended` test in `account::account::test` for more
    // explanation on some of the (inconsequential) differences from the RFC
    // here.

    let setup = set_up();
    let mut client = setup.connect("5258rfcx");
    quick_log_in(&mut client);

    quick_create(&mut client, "5258rfcx/Fruit");
    quick_create(&mut client, "5258rfcx/Fruit/Apple");
    quick_create(&mut client, "5258rfcx/Fruit/Banana");
    quick_create(&mut client, "5258rfcx/Tofu");
    quick_create(&mut client, "5258rfcx/Vegetable");
    quick_create(&mut client, "5258rfcx/Vegetable/Broccoli");
    quick_create(&mut client, "5258rfcx/Vegetable/Corn");

    ok_command!(client, c("SUBSCRIBE 5258rfcx/Fruit/Banana"));
    ok_command!(client, c("SUBSCRIBE 5258rfcx/Fruit/Peach"));
    ok_command!(client, c("SUBSCRIBE 5258rfcx/Vegetable"));
    ok_command!(client, c("SUBSCRIBE 5258rfcx/Vegetable/Broccoli"));

    macro_rules! assert_list_like {
        ($expected:expr, $command:expr) => {{
            command!(mut responses = client, c($command));
            assert_tagged_ok(responses.pop().unwrap());
            assert_eq!($expected, list_results_to_str(responses));
        }};
    }

    // Example 5.1
    assert_list_like!(
        "5258rfcx/Fruit\n\
         5258rfcx/Fruit/Apple\n\
         5258rfcx/Fruit/Banana\n\
         5258rfcx/Tofu\n\
         5258rfcx/Vegetable\n\
         5258rfcx/Vegetable/Broccoli\n\
         5258rfcx/Vegetable/Corn\n",
        "LIST \"\" (5258rfcx/*)"
    );

    // Example 5.2
    assert_list_like!(
        "5258rfcx/Fruit/Banana \\Subscribed\n\
         5258rfcx/Fruit/Peach \\NonExistent \\Subscribed\n\
         5258rfcx/Vegetable \\Subscribed\n\
         5258rfcx/Vegetable/Broccoli \\Subscribed\n",
        "LIST (SUBSCRIBED) \"\" 5258rfcx/*"
    );

    // Example 5.3
    assert_list_like!(
        "5258rfcx/Fruit \\HasChildren\n\
         5258rfcx/Tofu \\HasNoChildren\n\
         5258rfcx/Vegetable \\HasChildren\n",
        "LIST \"\" 5258rfcx/% RETURN (CHILDREN)"
    );

    // Example 5.6
    assert_list_like!(
        "5258rfcx/Fruit\n\
         5258rfcx/Fruit/Apple\n\
         5258rfcx/Fruit/Banana \\Subscribed\n\
         5258rfcx/Tofu\n\
         5258rfcx/Vegetable \\Subscribed\n\
         5258rfcx/Vegetable/Broccoli \\Subscribed\n\
         5258rfcx/Vegetable/Corn\n",
        "LIST (REMOTE) \"\" 5258rfcx/* RETURN (SUBSCRIBED)"
    );

    // Example 5.7, adapted to the above hierarchy
    assert_list_like!(
        "5258rfcx/Fruit/Apple\n\
         5258rfcx/Fruit/Banana\n\
         5258rfcx/Vegetable\n\
         INBOX \\Noinferiors\n",
        "LIST \"\" (INBOX 5258rfcx/Fruit/% 5258rfcx/Vegetable)"
    );

    quick_create(&mut client, "5258rfcx2/Foo/Bar");
    quick_create(&mut client, "5258rfcx2/Foo/Baz");
    quick_create(&mut client, "5258rfcx2/Moo");

    // Example 5.8.?
    assert_list_like!(
        "5258rfcx2/Foo\n\
         5258rfcx2/Foo/Bar\n\
         5258rfcx2/Foo/Baz\n\
         5258rfcx2/Moo\n",
        "LIST \"\" (5258rfcx2/*)"
    );

    // Example 5.8.@
    assert_list_like!(
        "5258rfcx2/Foo \\HasChildren\n\
         5258rfcx2/Moo \\HasNoChildren\n",
        "LIST \"\" 5258rfcx2/% RETURN (CHILDREN)"
    );

    // Example 5.8.A
    ok_command!(client, c("SUBSCRIBE 5258rfcx2/Foo/Baz"));
    assert_list_like!(
        "5258rfcx2/Foo/Baz \\Subscribed\n",
        "LIST (SUBSCRIBED) \"\" 5258rfcx2/*"
    );
    assert_list_like!("", "LIST (SUBSCRIBED) \"\" 5258rfcx2/%");
    assert_list_like!(
        "5258rfcx2/Foo CHILDINFO SUBSCRIBED\n",
        "LIST (SUBSCRIBED RECURSIVEMATCH) \"\" 5258rfcx2/%"
    );

    // Example 5.8.A1
    ok_command!(client, c("SUBSCRIBE 5258rfcx2/Foo"));
    assert_list_like!(
        "5258rfcx2/Foo \\Subscribed CHILDINFO SUBSCRIBED\n",
        "LIST (SUBSCRIBED RECURSIVEMATCH) \"\" 5258rfcx2/%"
    );

    // Example 5.8.A2, names adapted to reuse hierarchy
    ok_command!(client, c("UNSUBSCRIBE 5258rfcx2/Foo"));
    ok_command!(client, c("UNSUBSCRIBE 5258rfcx2/Foo/Baz"));
    ok_command!(client, c("SUBSCRIBE 5258rfcx2/Xyzzy/Plugh"));
    assert_list_like!(
        "5258rfcx2/Xyzzy \\NonExistent CHILDINFO SUBSCRIBED\n",
        "LIST (RECURSIVEMATCH SUBSCRIBED) \"\" 5258rfcx2/%"
    );

    // Example 5.8.B
    ok_command!(client, c("UNSUBSCRIBE 5258rfcx2/Xyzzy/Plugh"));
    assert_list_like!("", "LIST (RECURSIVEMATCH SUBSCRIBED) \"\" 5258rfcx2/%");

    // Example 5.8.C
    ok_command!(client, c("SUBSCRIBE 5258rfcx2/Foo"));
    ok_command!(client, c("SUBSCRIBE 5258rfcx2/Moo"));
    assert_list_like!(
        "5258rfcx2/Foo \\HasChildren \\Subscribed\n\
         5258rfcx2/Moo \\HasNoChildren \\Subscribed\n",
        "LIST (RECURSIVEMATCH SUBSCRIBED) \"\" 5258rfcx2/% RETURN (CHILDREN)"
    );

    // Example 5.9
    quick_create(&mut client, "5258rfcx3/foo2");
    quick_create(&mut client, "5258rfcx3/foo2/bar1");
    quick_create(&mut client, "5258rfcx3/foo2/bar2");
    quick_create(&mut client, "5258rfcx3/baz2");
    quick_create(&mut client, "5258rfcx3/baz2/bar2");
    quick_create(&mut client, "5258rfcx3/baz2/bar22");
    quick_create(&mut client, "5258rfcx3/baz2/bar222");
    quick_create(&mut client, "5258rfcx3/eps2");
    quick_create(&mut client, "5258rfcx3/eps2/mamba");
    quick_create(&mut client, "5258rfcx3/qux2/bar2");

    ok_command!(client, c("SUBSCRIBE 5258rfcx3/foo2/bar1"));
    ok_command!(client, c("SUBSCRIBE 5258rfcx3/foo2/bar2"));
    ok_command!(client, c("SUBSCRIBE 5258rfcx3/baz2/bar2"));
    ok_command!(client, c("SUBSCRIBE 5258rfcx3/baz2/bar22"));
    ok_command!(client, c("SUBSCRIBE 5258rfcx3/baz2/bar222"));
    ok_command!(client, c("SUBSCRIBE 5258rfcx3/eps2"));
    ok_command!(client, c("SUBSCRIBE 5258rfcx3/eps2/mamba"));
    ok_command!(client, c("SUBSCRIBE 5258rfcx3/qux2/bar2"));

    assert_list_like!(
        "5258rfcx3/baz2/bar2 \\Subscribed\n\
         5258rfcx3/baz2/bar22 \\Subscribed\n\
         5258rfcx3/baz2/bar222 \\Subscribed\n\
         5258rfcx3/eps2 \\Subscribed CHILDINFO SUBSCRIBED\n\
         5258rfcx3/foo2 CHILDINFO SUBSCRIBED\n\
         5258rfcx3/foo2/bar2 \\Subscribed\n\
         5258rfcx3/qux2/bar2 \\Subscribed\n",
        "LIST (SUBSCRIBED RECURSIVEMATCH) \"\" 5258rfcx3/*2"
    );

    assert_list_like!(
        "5258rfcx3/baz2/bar2 \\Subscribed\n\
         5258rfcx3/baz2/bar22 \\Subscribed\n\
         5258rfcx3/baz2/bar222 \\Subscribed\n\
         5258rfcx3/eps2 \\Subscribed CHILDINFO SUBSCRIBED\n\
         5258rfcx3/eps2/mamba \\Subscribed\n\
         5258rfcx3/foo2/bar1 \\Subscribed\n\
         5258rfcx3/foo2/bar2 \\Subscribed\n\
         5258rfcx3/qux2/bar2 \\Subscribed\n",
        "LIST (SUBSCRIBED RECURSIVEMATCH) \"\" 5258rfcx3/*"
    );
}
