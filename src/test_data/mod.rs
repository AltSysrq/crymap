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

/// The example from Page 56 of RFC 3501
pub static RFC3501_P56: &[u8] = include_bytes!("rfc3501_p56.eml");

/// The 20 smallest messages in the Enron corpus which contain "multipart" and
/// have a line that looks like the final boundary of multipart content.
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
