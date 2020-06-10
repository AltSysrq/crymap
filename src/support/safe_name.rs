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

/// Determine whether the given name is "safe".
///
/// This is used to validate the names of items which are used as file system
/// elements. It excludes empty names and patterns that cause directory
/// traversal or other unwanted behaviours, as well as things that have special
/// meaning within IMAP.
///
/// This does not care about whether the name is ultimately a valid file name;
/// for that, we simply rely on the OS rejecting it. It also does not check for
/// the MS-DOS device names; if we ever want first-class Windows support,
/// something will need to be done there (probably involving use of `\\?\` or
/// whatever it is to opt out of those weirdnesses, as well as things like ¥
/// being a path separator on Shift-JIS systems).
pub fn is_safe_name(name: &str) -> bool {
    !name.is_empty() &&
        // Block directory traversal through .. and creation of hidden files on
        // UNIX
        name.chars().next() != Some('.') &&
        name.find('/').is_none() &&
        // Only a path separator on Windows, but always block since it has high
        // potential of causing problems
        name.find('\\').is_none() &&
        // Names beginning with # have special meaning in IMAP
        name.chars().next() != Some('#') &&
        // Don't allow any ASCII control characters
        name.find(|c| c < ' ' || c == '\x7F').is_none() &&
        // * and % are very special in *some* IMAP contexts, so forbid
        // everywhere
        name.find(|c| c == '*' || c == '%').is_none()
}

#[cfg(test)]
mod test {
    use super::is_safe_name;

    #[test]
    fn test_is_safe_name() {
        assert!(is_safe_name("foo"));
        assert!(is_safe_name("PRN"));
        assert!(is_safe_name("Entwürfe"));
        assert!(is_safe_name("郵便"));
        assert!(is_safe_name("foo.bar"));
        assert!(is_safe_name("folder #1"));
        assert!(!is_safe_name("."));
        assert!(!is_safe_name(".."));
        assert!(!is_safe_name(".hidden"));
        assert!(!is_safe_name("foo/bar"));
        assert!(!is_safe_name("/foo"));
        assert!(!is_safe_name("foo/"));
        assert!(!is_safe_name("foo\\bar"));
        assert!(!is_safe_name("#news"));
        assert!(!is_safe_name("foo\0"));
        assert!(!is_safe_name("foo\r"));
        assert!(!is_safe_name("fo\x7Fo"));
        assert!(!is_safe_name("foo*bar"));
        assert!(!is_safe_name("foo%bar"));
    }
}
