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

/// The example from Page 56 of RFC 3501
pub static RFC3501_P56: &[u8] = include_bytes!("rfc3501_p56.eml");

/// The 20 smallest messages in the Enron corpus which contain "multipart" and
/// have a line that looks like the final boundary of multipart content.
///
/// Unfortunately, none of them are actually multiparts. Most are forwarded
/// messages by some agent that apparently felt it was appropriate to include
/// the raw multipart structure in the quoted part as text; others are attempts
/// to be multipart but completely malformed.
pub static ENRON_SMALL_MULTIPARTS: &[&[u8]] = &[
    include_bytes!("enron_dasovich-j_all_documents_11634.eml"),
    include_bytes!("enron_dasovich-j_notes_inbox_3944.eml"),
    include_bytes!("enron_farmer-d_all_documents_3128.eml"),
    include_bytes!("enron_farmer-d_discussion_threads_4965.eml"),
    include_bytes!("enron_farmer-d_entex_106.eml"),
    include_bytes!("enron_farmer-d_entex_1.eml"),
    include_bytes!("enron_keavey-p_deleted_items_127.eml"),
    include_bytes!("enron_keavey-p_deleted_items_144.eml"),
    include_bytes!("enron_keavey-p_deleted_items_163.eml"),
    include_bytes!("enron_keavey-p_deleted_items_21.eml"),
    include_bytes!("enron_keavey-p_deleted_items_258.eml"),
    include_bytes!("enron_keavey-p_deleted_items_269.eml"),
    include_bytes!("enron_keavey-p_deleted_items_314.eml"),
    include_bytes!("enron_keavey-p_deleted_items_55.eml"),
    include_bytes!("enron_keavey-p_deleted_items_63.eml"),
    include_bytes!("enron_keavey-p_deleted_items_6.eml"),
    include_bytes!("enron_keavey-p_deleted_items_82.eml"),
    include_bytes!("enron_keavey-p_inbox_551.eml"),
    include_bytes!("enron_scholtes-d_transmission_29.eml"),
    include_bytes!("enron_scholtes-d_transmission_35.eml"),
];

/// Mark Crispin's "MIME torture test".
/// > In the name of "a picture is worth 1000 words", take a look at the
/// > infamous MIME Torture Test message at:
/// >   ftp://ftp.cac.washington.edu/mail/mime-examples/torture-test.mbox
/// > It's horrible, and few MIME parsers pass it the first time.
///
/// Extraneous stuff from the mbox format removed and converted to DOS-style
/// line endings.
///
/// Note that the file contains lines with trailing whitespace, which is
/// significant to the tests that use it.
pub static TORTURE_TEST: &[u8] = include_bytes!("torture-test.eml");

/// A syntactically simple message with every interesting header field set.
pub static CHRISTMAS_TREE: &[u8] = include_bytes!("christmas-tree.eml");

/// A message with various obsolete route syntax included.
pub static WITH_OBSOLETE_ROUTING: &[u8] =
    include_bytes!("with-obsolete-routing.eml");

/// This message exposed a bug in the way header wrapping is handled.
pub static DOVECOT_PREFER_STANDALONE_DAEMONS: &[u8] =
    include_bytes!("dovecot-prefer-standalone-daemons.eml");

/// A message with an unknown Content-Transfer-Encoding.
pub static UNKNOWN_CTE: &[u8] = include_bytes!("unknown-cte.eml");

/// A single-part message with base64-encoded content.
pub static SINGLE_PART_BASE64: &[u8] = include_bytes!("single-part-base64.eml");

/// A multi-part message with two base64-encoded parts, one of which contains
/// an encoded NUL byte.
pub static MULTI_PART_BASE64: &[u8] = include_bytes!("multi-part-base64.eml");

/// Message sent by lin.gl (using dkim-proxy) with `rsa-sha1` DKIM and
/// `relaxed/strict` canonicalisation.
pub static DKIM_LINGL_RSA_SHA1: &[u8] =
    include_bytes!("dkim-lingl-rsa-sha1.eml");

/// Message sent by Amazon SES with 2 `rsa-sha256` DKIM signatures using
/// `relaxed/strict` canonicalisation and different headers on each signature.
///
/// Note that the domain key for the `amazon.co.jp` signature has been revoked
/// and the original value is not known.
pub static DKIM_AMAZONCOJP_RSA_SHA256: &[u8] =
    include_bytes!("dkim-amazoncojp-2x-rsa-sha256.eml");

/// Message sent by Yahoo! with `rsa-sha256` DKIM and `relaxed/relaxed`
/// canonicalisation. The main message body includes duplicated and
/// leading/trailing space which is subject to canonicalisation.
pub static DKIM_YAHOO_RSA_SHA256: &[u8] =
    include_bytes!("dkim-yahoo-rsa-sha256.eml");

lazy_static::lazy_static! {
    pub static ref CERTIFICATE_PRIVATE_KEY: openssl::pkey::PKey<openssl::pkey::Private> =
        openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap())
            .unwrap();
    pub static ref CERTIFICATE: openssl::x509::X509 = {
        let mut builder = openssl::x509::X509Builder::new().unwrap();
        builder.set_pubkey(&CERTIFICATE_PRIVATE_KEY).unwrap();
        builder
            .sign(
                &CERTIFICATE_PRIVATE_KEY,
                openssl::hash::MessageDigest::sha256(),
            )
            .unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_not_before(&openssl::asn1::Asn1Time::from_unix(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&openssl::asn1::Asn1Time::days_from_now(2).unwrap())
            .unwrap();
        builder.build()
    };
}
