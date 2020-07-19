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

use std::borrow::Cow;
use std::marker::PhantomData;

use chrono::prelude::*;

use super::super::defs::*;
use crate::account::model::Flag;
use crate::imap::literal_source::LiteralSource;
use crate::support::error::Error;
use crate::test_data::*;

macro_rules! fetch_single {
    ($client:expr, $cmd:expr, $fr:pat => $result:expr) => {{
        command!(mut responses = $client, $cmd);
        assert_eq!(2, responses.len());
        assert_tagged_ok(responses.pop().unwrap());
        match responses.pop().unwrap() {
            s::ResponseLine {
                tag: None,
                response: s::Response::Fetch($fr),
            } => $result,
            r => panic!("Unexpected response: {:?}", r),
        }
    }};
}

#[test]
fn fetch_single_scalars() {
    let setup = set_up();
    let mut client = setup.connect("3501fess");
    quick_log_in(&mut client);
    examine_shared(&mut client);

    fetch_single!(client, c("FETCH * UID"), ref fr => {
        assert_eq!(21, fr.seqnum);
        has_msgatt_matching! {
            s::MsgAtt::Uid(22) in fr
        };
    });

    fetch_single!(client, c("FETCH 1 FLAGS"), ref fr => {
        assert_eq!(1, fr.seqnum);
        has_msgatt_matching! {
            s::MsgAtt::Flags(s::FlagsFetch::NotRecent(ref flags)) in fr => {
                assert_eq!(&[Flag::Answered], &flags[..]);
            }
        };
    });

    fetch_single!(client, c("UID FETCH 22 INTERNALDATE"), ref fr => {
        assert_eq!(21, fr.seqnum);
        has_msgatt_matching! {
            s::MsgAtt::InternalDate(id) in fr => {
                assert_eq!(22, id.day());
            }
        };

        // UID FETCH implicitly includes UID
        has_msgatt_matching! {
            s::MsgAtt::Uid(22) in fr
        };
    });

    fetch_single!(client, c("FETCH 2 RFC822.SIZE"), ref fr => {
        has_msgatt_matching! {
            s::MsgAtt::Rfc822Size(1845473) in fr
        };
    });
}

#[test]
fn fetch_envelope() {
    let setup = set_up();
    let mut client = setup.connect("3501feev");
    quick_log_in(&mut client);
    examine_shared(&mut client);

    let expected_envelope = s::Envelope {
        date: Some(Cow::Borrowed("Fri, 21 Nov 1997 09:55:06 -0600")),
        subject: Some(Cow::Borrowed("This is the subject")),
        from: vec![s::Address::Real(s::RealAddress {
            display_name: None,
            routing: None,
            local_part: Cow::Borrowed("from"),
            domain: Cow::Borrowed("example.com"),
        })],
        sender: vec![s::Address::Real(s::RealAddress {
            display_name: None,
            routing: None,
            local_part: Cow::Borrowed("sender"),
            domain: Cow::Borrowed("example.com"),
        })],
        reply_to: vec![s::Address::Real(s::RealAddress {
            display_name: None,
            routing: None,
            local_part: Cow::Borrowed("reply-to"),
            domain: Cow::Borrowed("example.com"),
        })],
        to: vec![
            s::Address::GroupDelim(Some(Cow::Borrowed(
                "=?utf-8?b?QSBNw6RpbGluZyBMaXN0?=",
            ))),
            s::Address::Real(s::RealAddress {
                display_name: Some(Cow::Borrowed(
                    "=?utf-8?b?VMO2bSBPcndlbGw?=",
                )),
                routing: None,
                local_part: Cow::Borrowed("to"),
                domain: Cow::Borrowed("example.com"),
            }),
            s::Address::GroupDelim(None),
        ],
        cc: vec![s::Address::Real(s::RealAddress {
            display_name: None,
            routing: None,
            local_part: Cow::Borrowed("cc"),
            domain: Cow::Borrowed("example.com"),
        })],
        bcc: vec![s::Address::Real(s::RealAddress {
            display_name: None,
            routing: None,
            local_part: Cow::Borrowed("bcc"),
            domain: Cow::Borrowed("example.com"),
        })],
        in_reply_to: Some(Cow::Borrowed("<inreplyto@example.com>")),
        message_id: Some(Cow::Borrowed("<messageid@example.com>")),
    };

    fetch_single!(client, c("FETCH 1 ENVELOPE"), ref fr => {
        has_msgatt_matching! {
            s::MsgAtt::Envelope(ref envelope) in fr => {
                assert_eq!(&expected_envelope, envelope);
            }
        };
    });

    let expected_envelope = s::Envelope {
        date: Some(Cow::Borrowed("Wed, 25 Apr 2001 14:59:00 -0700")),
        subject: Some(Cow::Borrowed("Fwd: failure delivery")),
        from: vec![s::Address::Real(s::RealAddress {
            display_name: None,
            routing: None,
            local_part: Cow::Borrowed("asama"),
            domain: Cow::Borrowed("yahoo.com"),
        })],
        // These two are implicitly copied from `from`
        sender: vec![s::Address::Real(s::RealAddress {
            display_name: None,
            routing: None,
            local_part: Cow::Borrowed("asama"),
            domain: Cow::Borrowed("yahoo.com"),
        })],
        reply_to: vec![s::Address::Real(s::RealAddress {
            display_name: None,
            routing: None,
            local_part: Cow::Borrowed("asama"),
            domain: Cow::Borrowed("yahoo.com"),
        })],
        to: vec![
            s::Address::Real(s::RealAddress {
                display_name: None,
                routing: None,
                local_part: Cow::Borrowed("dasovic"),
                domain: Cow::Borrowed("enron.com"),
            }),
            s::Address::Real(s::RealAddress {
                display_name: None,
                routing: None,
                local_part: Cow::Borrowed("dasovich"),
                domain: Cow::Borrowed("haas.berkeley.edu"),
            }),
        ],
        cc: vec![],
        bcc: vec![],
        in_reply_to: None,
        message_id: Some(Cow::Borrowed(
            "<2078948.1075843446892.JavaMail.evans@thyme>",
        )),
    };

    fetch_single!(client, c("FETCH 3 ENVELOPE"), ref fr => {
        has_msgatt_matching! {
            s::MsgAtt::Envelope(ref envelope) in fr => {
                assert_eq!(&expected_envelope, envelope);
            }
        };
    });
}

#[test]
fn fetch_envelope_with_obsolete_routes() {
    let setup = set_up();
    let mut client = setup.connect("3501feor");
    quick_log_in(&mut client);
    quick_create(&mut client, "3501feor");
    quick_select(&mut client, "3501feor");

    client
        .start_append(
            "3501feor",
            s::AppendFragment {
                flags: None,
                internal_date: None,
                _marker: PhantomData,
            },
            WITH_OBSOLETE_ROUTING,
        )
        .unwrap();

    let mut buffer = Vec::new();
    let mut responses = client.finish_append(&mut buffer).unwrap();
    assert_tagged_ok_any(responses.pop().unwrap());

    fetch_single!(client, c("FETCH 1 ENVELOPE"), ref fr => {
        has_msgatt_matching! {
            s::MsgAtt::Envelope(ref envelope) in fr => {
                assert_eq!(vec![
                    s::Address::Real(s::RealAddress {
                        display_name: None,
                        routing: Some(Cow::Borrowed("@route1.tld")),
                        local_part: Cow::Borrowed("foo"),
                        domain: Cow::Borrowed("bar.com"),
                    }),
                ], envelope.from);
                assert_eq!(vec![
                    s::Address::Real(s::RealAddress {
                        display_name: None,
                        routing: Some(Cow::Borrowed("@route2.tld,@route3")),
                        local_part: Cow::Borrowed("baz"),
                        domain: Cow::Borrowed("quux.com"),
                    }),
                ], envelope.to);
            }
        };
    });
}

#[test]
fn fetch_body_structure() {
    let setup = set_up();
    let mut client = setup.connect("3501febs");
    quick_log_in(&mut client);
    examine_shared(&mut client);

    fetch_single!(client, c("FETCH 1 BODY"), ref fr => {
        has_msgatt_matching! {
            s::MsgAtt::ShortBodyStructure(ref bs) in fr => {
                check_christmass_tree_body_structure(bs, false);
            }
        };
    });

    fetch_single!(client, c("FETCH 1 BODYSTRUCTURE"), ref fr => {
        has_msgatt_matching! {
            s::MsgAtt::ExtendedBodyStructure(ref bs) in fr => {
                check_christmass_tree_body_structure(bs, true);
            }
        };
    });

    fetch_single!(client, c("FETCH 2 BODY"), ref fr => {
        has_msgatt_matching! {
            s::MsgAtt::ShortBodyStructure(ref bs) in fr => {
                check_torture_test_body_structure(bs, false);
            }
        };
    });

    fetch_single!(client, c("FETCH 2 BODYSTRUCTURE"), ref fr => {
        has_msgatt_matching! {
            s::MsgAtt::ExtendedBodyStructure(ref bs) in fr => {
                check_torture_test_body_structure(bs, true);
            }
        };
    });
}

fn check_christmass_tree_body_structure(bs: &s::Body<'_>, extended: bool) {
    let bs = match *bs {
        s::Body::SinglePart(ref bs) => bs,
        ref bs => panic!("Unexpected top-level body structure: {:#?}", bs),
    };

    let core = match bs.core {
        s::ClassifiedBodyType1Part::Text(ref text) => text,
        ref core => panic!("Unexpected core structure: {:#?}", core),
    };
    assert_eq!(
        &s::BodyTypeText {
            media_subtype: Cow::Borrowed("rich"),
            body_fields: s::BodyFields {
                content_type_parms: vec![
                    Cow::Borrowed("charset"),
                    Cow::Borrowed("utf-8"),
                    Cow::Borrowed("richness"),
                    Cow::Borrowed("low"),
                ],
                content_id: Some(Cow::Borrowed("<contentid@example.com>")),
                content_description: Some(Cow::Borrowed("A test message")),
                content_transfer_encoding: Cow::Borrowed("8bit"),
                size_octets: 85,
            },
            size_lines: 2,
        },
        core
    );

    if extended {
        assert_eq!(
            Some(s::BodyExt1Part {
                md5: Some(Cow::Borrowed("e874f86d668f69c35b59c901c8442719")),
                content_disposition: Some(s::ContentDisposition {
                    disposition: Cow::Borrowed("attachment"),
                    parms: vec![
                        Cow::Borrowed("name"),
                        Cow::Borrowed("foo.txt"),
                    ],
                }),
                content_language: Some(Cow::Borrowed("en")),
                content_location: Some(Cow::Borrowed("/foo/bar")),
            }),
            bs.ext
        );
    } else {
        assert!(bs.ext.is_none());
    }
}

fn check_torture_test_body_structure(bs: &s::Body<'_>, extended: bool) {
    // We don't check the whole body structure here. The more thorough test is
    // done by the tests in `bodystructure.rs`. The purpose of this test is to
    // ensure that the correct fields are assigned the correct values in the
    // varying body structure types.
    //
    // In other words, we look at one non-text single part, one message part,
    // and one multipart.
    let bs = match *bs {
        s::Body::Multipart(ref bs) => bs,
        ref bs => panic!("Unexpected top-level body structure: {:#?}", bs),
    };

    assert_eq!("MIXED", bs.media_subtype);

    if extended {
        assert_eq!(
            Some(s::BodyExtMPart {
                content_type_parms: vec![
                    Cow::Borrowed("boundary"),
                    Cow::Borrowed("owatagusiam"),
                ],
                content_disposition: Some(s::ContentDisposition {
                    disposition: Cow::Borrowed("inline"),
                    parms: vec![
                        Cow::Borrowed("name"),
                        Cow::Borrowed("torture"),
                    ],
                }),
                content_language: Some(Cow::Borrowed("en")),
                content_location: Some(Cow::Borrowed("/plugh")),
            }),
            bs.ext
        );
    } else {
        assert!(bs.ext.is_none());
    }

    // Part 2 is a message/rfc822 containing a multipart
    let p2 = match bs.bodies[1] {
        s::Body::SinglePart(ref p2) => p2,
        ref p2 => panic!("Unexpected structure for part 2: {:#?}", p2),
    };
    let p2_core = match p2.core {
        s::ClassifiedBodyType1Part::Message(ref p2c) => p2c,
        ref p2c => panic!("Unexpected core structure for part 2: {:#?}", p2c),
    };
    assert_eq!(
        s::BodyFields {
            content_type_parms: vec![],
            content_id: None,
            content_description: Some(Cow::Borrowed("Rich Text demo")),
            content_transfer_encoding: Cow::Borrowed("7bit"),
            size_octets: 4906,
        },
        p2_core.body_fields
    );
    assert_eq!(
        vec![s::Address::Real(s::RealAddress {
            display_name: Some(Cow::Borrowed("Nathaniel Borenstein")),
            routing: None,
            local_part: Cow::Borrowed("nsb"),
            domain: Cow::Borrowed("thumper.bellcore.com"),
        })],
        p2_core.envelope.from
    );
    assert_eq!(106, p2_core.size_lines);

    if extended {
        assert_eq!(
            Some(s::BodyExt1Part {
                md5: Some(Cow::Borrowed("01bf6a12f89ac63b1962d39b09385771")),
                content_disposition: None,
                content_language: None,
                content_location: None,
            }),
            p2.ext
        );
    } else {
        assert!(p2.ext.is_none());
    }

    let p2m = match *p2_core.body {
        s::Body::Multipart(ref p2m) => p2m,
        ref p2m => panic!("Unexpected structure for Part 2 inner: {:#?}", p2m),
    };

    // Part 2.3 is an application/andrew-inset
    let p23 = match p2m.bodies[2] {
        s::Body::SinglePart(ref p23) => p23,
        ref p23 => panic!("Unexpected structure for Part 2.3: {:#?}", p23),
    };
    let p23_core = match p23.core {
        s::ClassifiedBodyType1Part::Basic(ref p23c) => p23c,
        ref p23c => {
            panic!("Unexpected core structure for Part 2.3: {:#?}", p23c)
        }
    };
    assert_eq!("application", p23_core.media_type);
    assert_eq!("andrew-inset", p23_core.media_subtype);
    assert_eq!(
        s::BodyFields {
            content_type_parms: vec![],
            content_id: None,
            content_description: None,
            content_transfer_encoding: Cow::Borrowed("7bit"),
            size_octets: 917,
        },
        p23_core.body_fields
    );

    if extended {
        assert_eq!(
            Some(s::BodyExt1Part {
                md5: Some(Cow::Borrowed("9f7f13a2dfad1454eee9454146510303")),
                content_disposition: None,
                content_language: None,
                content_location: None,
            }),
            p23.ext
        );
    } else {
        assert!(p23.ext.is_none());
    }

    // Part 3 is a message/rfc822 containing a single part
    let p3 = match bs.bodies[2] {
        s::Body::SinglePart(ref p3) => p3,
        ref p3 => panic!("Unexpected structure for part 3: {:#?}", p3),
    };
    let p3_core = match p3.core {
        s::ClassifiedBodyType1Part::Message(ref p3c) => p3c,
        ref p3c => panic!("Unexpected core structure for part 3: {:#?}", p3c),
    };
    assert_eq!(
        s::BodyFields {
            content_type_parms: vec![],
            content_id: None,
            content_description: Some(Cow::Borrowed("Voice Mail demo")),
            content_transfer_encoding: Cow::Borrowed("7bit"),
            size_octets: 562270,
        },
        p3_core.body_fields
    );
    assert_eq!(
        vec![s::Address::Real(s::RealAddress {
            display_name: Some(Cow::Borrowed("Nathaniel Borenstein")),
            routing: None,
            local_part: Cow::Borrowed("nsb"),
            domain: Cow::Borrowed("thumper.bellcore.com"),
        })],
        p3_core.envelope.from
    );
    assert_eq!(7605, p3_core.size_lines);

    if extended {
        assert_eq!(
            Some(s::BodyExt1Part {
                md5: Some(Cow::Borrowed("58779ffa1437b598d5dc432e8095ae8f")),
                content_disposition: None,
                content_language: None,
                content_location: None,
            }),
            p3.ext
        );
    } else {
        assert!(p3.ext.is_none());
    }
}

#[test]
fn fetch_body_parts() {
    let setup = set_up();
    let mut client = setup.connect("3501febp");
    quick_log_in(&mut client);
    examine_shared(&mut client);

    fetch_single!(client, c("FETCH 1 RFC822"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Rfc822Full(lit) in fr => {
                assert_literal_like(
                    b"Remark:", b"even death may die.\r\n", 937, false, lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 1 RFC822.HEADER"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Rfc822Header(lit) in fr => {
                assert_literal_like(
                    b"Remark:", b"Encoding: 8bit\r\n\r\n", 0, false, lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 1 RFC822.TEXT"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Rfc822Text(lit) in fr => {
                assert_literal_like(
                    b"That is not dead which can eternal lie.\r\n",
                    "And with strange æons even death may die.\r\n".as_bytes(),
                    0, false, lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 1 BODY[]"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Body(s::MsgAttBody {
                section: None,
                slice_origin: None,
                data: lit,
            }) in fr => {
                assert_literal_like(
                    b"Remark:", b"even death may die.\r\n", 937, false, lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 1 BODY[HEADER]"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Body(s::MsgAttBody {
                section: Some(s::SectionSpec::TopLevel(
                    s::SectionText::Header(()))),
                slice_origin: None,
                data: lit,
            }) in fr => {
                assert_literal_like(
                    b"Remark:", b"Encoding: 8bit\r\n\r\n", 0, false, lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 1 BODY[HEADER.FIELDS (From To)]"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Body(s::MsgAttBody {
                section: Some(s::SectionSpec::TopLevel(
                    s::SectionText::HeaderFields(s::SectionTextHeaderField {
                        negative: false,
                        headers
                    }))),
                slice_origin: None,
                data: lit,
            }) in fr => {
                assert_eq!(vec![Cow::Borrowed("From"), Cow::Borrowed("To")],
                           headers);
                assert_literal_like(
                    b"From:", b"<to@example.com>;\r\n\r\n", 0, false, lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 1 BODY[HEADER.FIELDS.NOT \
                             (Remark Content-Transfer-Encoding)]"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Body(s::MsgAttBody {
                section: Some(s::SectionSpec::TopLevel(
                    s::SectionText::HeaderFields(s::SectionTextHeaderField {
                        negative: true,
                        headers
                    }))),
                slice_origin: None,
                data: lit,
            }) in fr => {
                assert_eq!(vec![Cow::Borrowed("Remark"),
                                Cow::Borrowed("Content-Transfer-Encoding")],
                           headers);
                assert_literal_like(
                    b"From:", b"A test message\r\n\r\n", 0, false, lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 1 BODY[TEXT]"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Body(s::MsgAttBody {
                section: Some(s::SectionSpec::TopLevel(
                    s::SectionText::Text(()))),
                slice_origin: None,
                data: lit,
            }) in fr => {
                assert_literal_like(
                    b"That is not dead which can eternal lie.\r\n",
                    "And with strange æons even death may die.\r\n".as_bytes(),
                    0, false, lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 2 BODY[1]"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Body(s::MsgAttBody {
                section: Some(s::SectionSpec::Sub(s::SubSectionSpec {
                    subscripts,
                    text: None,
                })),
                slice_origin: None,
                data: lit,
            }) in fr => {
                assert_eq!(vec![1], subscripts);
                assert_literal_like(
                    b"This is a demonstration",
                    b"new multi-part message standard.\r\n",
                    0,
                    false,
                    lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 2 BODY[1.MIME]"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Body(s::MsgAttBody {
                section: Some(s::SectionSpec::Sub(s::SubSectionSpec {
                    subscripts,
                    text: Some(s::SectionText::Mime(())),
                })),
                slice_origin: None,
                data: lit,
            }) in fr => {
                assert_eq!(vec![1], subscripts);
                assert_literal_like(
                    b"Content-Type: TEXT/PLAIN",
                    b"Content-Description: Explanation\r\n\r\n",
                    0,
                    false,
                    lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 2 BODY[2.MIME]"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Body(s::MsgAttBody {
                section: Some(s::SectionSpec::Sub(s::SubSectionSpec {
                    subscripts,
                    text: Some(s::SectionText::Mime(())),
                })),
                slice_origin: None,
                data: lit,
            }) in fr => {
                assert_eq!(vec![2], subscripts);
                assert_literal_like(
                    b"Content-Type: MESSAGE/RFC822",
                    b"Content-Description: Rich Text demo\r\n\r\n",
                    0,
                    false,
                    lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 2 BODY[2.HEADER]"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Body(s::MsgAttBody {
                section: Some(s::SectionSpec::Sub(s::SubSectionSpec {
                    subscripts,
                    text: Some(s::SectionText::Header(())),
                })),
                slice_origin: None,
                data: lit,
            }) in fr => {
                assert_eq!(vec![2], subscripts);
                assert_literal_like(
                    b"Received: from dimacs.rutgers",
                    b"Subject: Re: a MIME-Version misfeature\r\n\r\n",
                    0,
                    false,
                    lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 2 BODY[2.TEXT]"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Body(s::MsgAttBody {
                section: Some(s::SectionSpec::Sub(s::SubSectionSpec {
                    subscripts,
                    text: Some(s::SectionText::Text(())),
                })),
                slice_origin: None,
                data: lit,
            }) in fr => {
                assert_eq!(vec![2], subscripts);
                assert_literal_like(
                    b"This message has been composed",
                    b"mu0M2YtJKaFk=--\r\n",
                    0,
                    false,
                    lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 1 BODY[]<1.5>"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Body(s::MsgAttBody {
                section: None,
                slice_origin: Some(1),
                data: lit,
            }) in fr => {
                assert_literal_like(b"emark", b"", 5, false, lit);
            }
        };
    });

    fetch_single!(client, c("FETCH 1 BODY[]<0.5000>"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Body(s::MsgAttBody {
                section: None,
                slice_origin: Some(0),
                data: lit,
            }) in fr => {
                assert_literal_like(
                    b"Remark:", b"even death may die.\r\n", 937, false, lit);
            }
        };
    });
}

fn assert_literal_like(
    start: &[u8],
    end: &[u8],
    len: u64,
    binary: bool,
    mut lit: LiteralSource,
) {
    if 0 != len {
        assert_eq!(len, lit.len);
    }
    assert_eq!(binary, lit.binary);

    let mut data = Vec::<u8>::new();
    lit.data.read_to_end(&mut data).unwrap();
    if 0 != len {
        assert_eq!(len as usize, data.len());
    }
    assert_eq!(lit.len as usize, data.len());
    assert!(
        data.starts_with(start),
        "Data didn't have expected prefix; got:\n{}",
        String::from_utf8_lossy(&data)
    );
    assert!(
        data.ends_with(end),
        "Data didn't have expected end; got:\n{}",
        String::from_utf8_lossy(&data)
    );
}

#[test]
fn implicit_seen() {
    let setup = set_up();
    let mut client = setup.connect("3501feis");
    quick_log_in(&mut client);
    quick_create(&mut client, "3501feis");
    quick_append_enron(&mut client, "3501feis", 2);

    ok_command!(client, c("EXAMINE 3501feis"));
    // Nothing we do during EXAMINE should have any effect
    ok_command!(client, c("FETCH 1 RFC822"));
    ok_command!(client, c("UID FETCH 1 BODY[]"));

    fetch_single!(client, c("FETCH 1 FLAGS"), ref fr => {
        has_msgatt_matching! {
            s::MsgAtt::Flags(s::FlagsFetch::Recent(ref flags)) in fr => {
                assert!(flags.is_empty());
            }
        };
    });

    ok_command!(client, c("SELECT 3501feis"));
    // RFC822.SIZE, RFC822.HEADER, and BODY.PEEK don't cause an implicit \Seen
    // status
    ok_command!(client, c("FETCH 1 RFC822.SIZE"));
    ok_command!(client, c("FETCH 1 RFC822.HEADER"));
    ok_command!(client, c("FETCH 1 BODY.PEEK[]"));

    fetch_single!(client, c("FETCH 1 FLAGS"), ref fr => {
        has_msgatt_matching! {
            s::MsgAtt::Flags(s::FlagsFetch::Recent(ref flags)) in fr => {
                assert!(flags.is_empty());
            }
        };
    });

    // Fetching the IMAP4-style body without .PEEK sets \Seen
    ok_command!(client, c("FETCH 1 BODY[]"));
    fetch_single!(client, c("FETCH 1 FLAGS"), ref fr => {
        has_msgatt_matching! {
            s::MsgAtt::Flags(s::FlagsFetch::Recent(ref flags)) in fr => {
                assert_eq!(&vec![Flag::Seen], flags);
            }
        };
    });

    // If we fetch the body and FLAGS at the same time, FLAGS reflects the new
    // \Seen status.
    // We can't use fetch_single! here since we also get an echo from the
    // change notification about the flag.
    command!(mut responses = client, c("FETCH 2 (FLAGS BODY[HEADER])"));
    assert_eq!(3, responses.len());
    assert_tagged_ok(responses.pop().unwrap());
    // The actual fetch response is always before the echo
    match responses.into_iter().next().unwrap() {
        s::ResponseLine {
            tag: None,
            response: s::Response::Fetch(fr),
        } => {
            has_msgatt_matching! {
                s::MsgAtt::Flags(s::FlagsFetch::Recent(ref flags)) in fr => {
                    assert_eq!(&vec![Flag::Seen], flags);
                }
            };

            // Also ensure this is the fetch response we think it is
            has_msgatt_matching! { s::MsgAtt::Body(..) in fr };
        }
        r => panic!("Unexpected response: {:?}", r),
    }
}

#[test]
fn error_conditions() {
    let setup = set_up();
    let mut client = setup.connect("3501feec");
    quick_log_in(&mut client);
    quick_create(&mut client, "3501feec");
    quick_append_enron(&mut client, "3501feec", 2);
    quick_select(&mut client, "3501feec");

    let mut client2 = setup.connect("3501feec2");
    quick_log_in(&mut client2);
    quick_select(&mut client2, "3501feec");

    // Expunge UID 2 without letting the first client remove that from its
    // seqnum mapping.
    ok_command!(client2, c("XVANQUISH 2"));
    ok_command!(client2, c("XPURGE"));

    // First attempt to fetch the expunged message - NO
    // We need to use BODY.PEEK[] or else it will try to store \Seen, which
    // causes it to become aware of the EXPUNGE command without needing to hit
    // disk.
    command!([response] = client, c("FETCH 2 BODY.PEEK[]"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::No,
         Some(s::RespTextCode::ExpungeIssued(())), _) = response => ()
    };

    // Second attempt to fetch the expunged message - BYE
    client.write_raw(b"F1 FETCH 2 BODY.PEEK[]\r\n").unwrap();
    let mut buffer = Vec::new();
    let response = client.read_one_response(&mut buffer).unwrap();
    unpack_cond_response! {
        (None, s::RespCondType::Bye,
         Some(s::RespTextCode::ClientBug(())), _) = response => ()
    };

    let mut client = setup.connect("3501feec");
    quick_log_in(&mut client);
    quick_select(&mut client, "3501feec");

    // Also do some flag storing to make the first client aware of UID 3 even
    // though it is not in the UID map.
    quick_append_enron(&mut client2, "3501feec", 1);
    ok_command!(client2, c("UID STORE 3 +FLAGS.SILENT (\\Seen)"));
    ok_command!(client, c("STORE 1 +FLAGS.SILENT (\\Seen)"));

    command!([response] = client, c("UID FETCH 3 BODY[]"));
    assert_error_response(
        response,
        Some(s::RespTextCode::ClientBug(())),
        Error::UnaddressableMessage,
    );

    ok_command!(client, c("NOOP"));

    command!([response] = client, c("FETCH 100 BODY[]"));
    unpack_cond_response! {
        (Some(_), s::RespCondType::Bad, _, _) = response => ()
    }

    // UID FETCH for messages not in the current set are allowed
    command!(mut responses = client, c("UID FETCH 1:* UID"));
    assert_eq!(3, responses.len());
    assert_tagged_ok(responses.pop().unwrap());
}

#[test]
fn wrapped_headers_not_mangled() {
    let setup = set_up();
    let mut client = setup.connect("3501fehm");
    quick_log_in(&mut client);
    quick_create(&mut client, "3501fehm");
    quick_select(&mut client, "3501fehm");

    client
        .start_append(
            "3501fehm",
            s::AppendFragment {
                flags: None,
                // This particular date (or something around it) is required to
                // get the bytes to line up in the right way to trigger the
                // bug.
                internal_date: Some(
                    FixedOffset::east(0).ymd(2003, 2, 26).and_hms(10, 58, 31),
                ),
                _marker: PhantomData,
            },
            DOVECOT_PREFER_STANDALONE_DAEMONS,
        )
        .unwrap();

    let mut buffer = Vec::new();
    let mut responses = client.finish_append(&mut buffer).unwrap();
    assert_tagged_ok_any(responses.pop().unwrap());

    fetch_single!(client, c("FETCH 1 BODY.PEEK[]"), fr => {
        has_msgatt_matching! {
            move s::MsgAtt::Body(s::MsgAttBody {
                section: None,
                slice_origin: None,
                data: lit,
            }) in fr => {
                assert_literal_like(
                    b"Received:", b"\r\n", 2954, false, lit);
            }
        };
    });
}
