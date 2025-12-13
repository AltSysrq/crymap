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
use std::fmt;

use chrono::prelude::*;

use super::grovel::Visitor;
use super::header;
use super::quoted_printable::qp_decode;
use super::utf7;
use crate::account::model::*;

/// Interposer for `Visitor` which performs content decoding.
///
/// Transfer encoding is always decoded. Optionally, this can also decode
/// non-UTF-8 charsets into UTF-8.
#[derive(Debug)]
pub struct ContentDecoder<V: ?Sized> {
    delegate: Box<V>,
    decode_charset: bool,

    content_transfer_encoding: header::ContentTransferEncoding,
    charset: Option<Vec<u8>>,

    decoder: Option<ContentDecoderImpl>,
}

struct ContentDecoderImpl {
    content_transfer_encoding: header::ContentTransferEncoding,
    charset_decoder: Option<encoding_rs::Decoder>,
    decode_utf7: bool,
    input_buffer: Vec<u8>,
    cte_buffer: Vec<u8>,
    charset_buffer: Vec<u8>,
}

impl fmt::Debug for ContentDecoderImpl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ContentDecoderImpl")
            .field("content_transfer_encoding", &self.content_transfer_encoding)
            .field(
                "charset_decoder",
                &self.charset_decoder.as_ref().map(|_| "<decoder>"),
            )
            .field("decode_utf7", &self.decode_utf7)
            .field("input_buffer", &self.input_buffer)
            .field("cte_buffer", &self.cte_buffer)
            .field("charset_decoder", &self.charset_buffer)
            .finish()
    }
}

impl<V: ?Sized> ContentDecoder<V> {
    pub fn new(delegate: Box<V>, decode_charset: bool) -> Self {
        ContentDecoder {
            delegate,
            decode_charset,

            content_transfer_encoding:
                header::ContentTransferEncoding::SevenBit,
            charset: None,

            decoder: None,
        }
    }

    pub fn inner_mut(&mut self) -> &mut V {
        &mut self.delegate
    }
}

impl<V: Visitor + ?Sized> Visitor for ContentDecoder<V> {
    type Output = V::Output;

    fn uid(&mut self, uid: Uid) -> Result<(), Self::Output> {
        self.delegate.uid(uid)
    }

    fn email_id(&mut self, id: &str) -> Result<(), Self::Output> {
        self.delegate.email_id(id)
    }

    fn last_modified(&mut self, modseq: Modseq) -> Result<(), Self::Output> {
        self.delegate.last_modified(modseq)
    }

    fn savedate(
        &mut self,
        savedate: DateTime<Utc>,
    ) -> Result<(), Self::Output> {
        self.delegate.savedate(savedate)
    }

    fn want_flags(&self) -> bool {
        self.delegate.want_flags()
    }

    fn flags(&mut self, flags: &[Flag]) -> Result<(), Self::Output> {
        self.delegate.flags(flags)
    }

    fn recent(&mut self) -> Result<(), Self::Output> {
        self.delegate.recent()
    }

    fn end_flags(&mut self) -> Result<(), Self::Output> {
        self.delegate.end_flags()
    }

    fn rfc822_size(&mut self, size: u32) -> Result<(), Self::Output> {
        self.delegate.rfc822_size(size)
    }

    fn metadata(
        &mut self,
        metadata: &MessageMetadata,
    ) -> Result<(), Self::Output> {
        self.delegate.metadata(metadata)
    }

    fn raw_line(&mut self, line: &[u8]) -> Result<(), Self::Output> {
        self.delegate.raw_line(line)
    }

    fn header(
        &mut self,
        raw: &[u8],
        name: &str,
        value: &[u8],
    ) -> Result<(), Self::Output> {
        if name.eq_ignore_ascii_case("Content-Transfer-Encoding") {
            self.content_transfer_encoding =
                header::parse_content_transfer_encoding(value)
                    .unwrap_or_default();
        }

        self.delegate.header(raw, name, value)
    }

    fn content_type(
        &mut self,
        ct: &header::ContentType<'_>,
    ) -> Result<(), Self::Output> {
        self.decode_charset &= ct.is_type("text");
        self.charset = ct.parm("charset").map(|c| c.to_vec());
        self.delegate.content_type(ct)
    }

    fn leaf_section(
        &mut self,
    ) -> Option<Box<dyn Visitor<Output = Self::Output>>> {
        self.delegate.leaf_section()
    }

    fn start_content(&mut self) -> Result<(), Self::Output> {
        let decode_utf7 = self.decode_charset
            && self
                .charset
                .as_ref()
                .is_some_and(|s| s.eq_ignore_ascii_case(b"UTF-7"));

        let charset_decoder = if !decode_utf7 && self.decode_charset {
            encoding_rs::Encoding::for_label_no_replacement(
                self.charset.as_deref().unwrap_or(b"us-ascii"),
            )
            .map(|e| e.new_decoder_with_bom_removal())
        } else {
            None
        };

        self.decoder = Some(ContentDecoderImpl {
            content_transfer_encoding: self.content_transfer_encoding,
            decode_utf7,
            charset_decoder,
            input_buffer: Vec::new(),
            cte_buffer: Vec::new(),
            charset_buffer: Vec::new(),
        });

        self.delegate.start_content()
    }

    fn content(&mut self, data: &[u8]) -> Result<(), Self::Output> {
        let data = self
            .decoder
            .as_mut()
            .expect("content() called before start_content()")
            .push_content(data);
        if !data.is_empty() {
            self.delegate.content(data)
        } else {
            Ok(())
        }
    }

    fn start_part(
        &mut self,
    ) -> Option<Box<dyn Visitor<Output = Self::Output>>> {
        self.delegate.start_part()
    }

    fn child_result(
        &mut self,
        child_result: Self::Output,
    ) -> Result<(), Self::Output> {
        self.delegate.child_result(child_result)
    }

    fn end(&mut self) -> Self::Output {
        if let Some(ref mut decoder) = self.decoder {
            if let Some(data) = decoder.finish() {
                if let Err(out) = self.delegate.content(data) {
                    return out;
                }
            }
        }

        // We might have something still sitting in the input or charset
        // buffer, but there's not much sensible we can do either way, so just
        // drop.
        self.delegate.end()
    }

    fn visit_default(&mut self) -> Result<(), Self::Output> {
        panic!("missing method on ContentDecoder")
    }
}

impl ContentDecoderImpl {
    fn push_content<'a, 'b: 'a>(&'b mut self, data: &'a [u8]) -> &'a [u8] {
        use super::header::ContentTransferEncoding as CTE;

        let data = match self.content_transfer_encoding {
            CTE::SevenBit | CTE::EightBit | CTE::Binary => data,
            CTE::Base64 => {
                self.decode_base64(data);
                &self.cte_buffer
            },
            CTE::QuotedPrintable => {
                self.decode_qp(data);
                &self.cte_buffer
            },
        };

        if self.decode_utf7 {
            // This looks like a somewhat halfhearted UTF-7 implementation, but
            // it's actually good enough for the standard.
            //
            // UTF-7 requires that we aren't "shifted in" across line
            // boundaries. As long as that holds, this is correct since content
            // is pushed one line at a time.
            //
            // Strictly though, there's nothing stopping anyone from using
            // base64 transfer encoding with UTF-7 (as pointless as that is),
            // in which case our content boundaries are meaningless. It's also
            // possible to use quoted-printable encoding to change exactly
            // where a "line boundary" is.
            //
            // However, RFC 2152 allows only quoted-printable for a
            // non-identity transfer encoding, and at least can be read in a
            // way that indicates that the "may not cross line breaks"
            // requirement refers to line breaks in the transfer encoding and
            // not the raw form.
            //
            // UTF-7 is already a vanishingly rare encoding, so it's not worth
            // the extra effort to deal with the pathological cases.
            let utf8 = String::from_utf8_lossy(data);
            let decoded = utf7::STD.decode(&utf8);
            self.charset_buffer.clear();
            self.charset_buffer.extend_from_slice(decoded.as_bytes());
            &self.charset_buffer
        } else if let Some(ref mut decoder) = self.charset_decoder {
            self.charset_buffer.resize(
                decoder
                    .max_utf8_buffer_length(data.len())
                    .expect("Chunk too large to fit into memory"),
                0,
            );
            let (status, _nread, nwritten, _wrote_replacement) =
                decoder.decode_to_utf8(data, &mut self.charset_buffer, false);
            debug_assert_eq!(encoding_rs::CoderResult::InputEmpty, status);

            &self.charset_buffer[..nwritten]
        } else {
            data
        }
    }

    fn decode_base64(&mut self, data: &[u8]) {
        self.cte_buffer.clear();

        let mut pushed_any = false;
        for &byte in data {
            match byte {
                b'0'..=b'9'
                | b'a'..=b'z'
                | b'A'..=b'Z'
                | b'+'
                | b'/'
                | b'=' => {
                    self.input_buffer.push(byte);
                    pushed_any = true;
                },
                _ => (),
            }
        }

        if pushed_any {
            let usable_length = self.input_buffer.len() / 4 * 4;
            let _ = base64::decode_config_buf(
                &self.input_buffer[..usable_length],
                base64::STANDARD,
                &mut self.cte_buffer,
            );

            self.input_buffer.copy_within(usable_length.., 0);
            self.input_buffer
                .truncate(self.input_buffer.len() - usable_length);
        }
    }

    fn decode_qp(&mut self, data: &[u8]) {
        self.cte_buffer.clear();

        if self.input_buffer.is_empty() {
            let (decoded, dangling) = qp_decode(data);
            self.input_buffer.extend_from_slice(dangling);

            match decoded {
                Cow::Owned(v) => self.cte_buffer = v,
                Cow::Borrowed(v) => self.cte_buffer.extend_from_slice(v),
            }
        } else {
            self.input_buffer.extend_from_slice(data);
            let consumed_len = {
                let (decoded, dangling) = qp_decode(&self.input_buffer);
                match decoded {
                    Cow::Owned(v) => self.cte_buffer = v,
                    Cow::Borrowed(v) => self.cte_buffer.extend_from_slice(v),
                }
                self.input_buffer.len() - dangling.len()
            };

            self.input_buffer.copy_within(consumed_len.., 0);
            self.input_buffer
                .truncate(self.input_buffer.len() - consumed_len);
        }
    }

    fn finish(&mut self) -> Option<&[u8]> {
        // If there's trailing CTE garbage in `input_buffer`, there's not
        // really anything we can do with it, so just discard it.
        // We do need to see if the charset decoder has anything left to say
        // though.
        if let Some(ref mut decoder) = self.charset_decoder {
            self.charset_buffer.resize(
                decoder
                    .max_utf8_buffer_length(0)
                    .expect("End of char conversion too big to fit in memory"),
                0,
            );
            let (_status, _nread, nwritten, _wrote_replacement) =
                decoder.decode_to_utf8(&[], &mut self.charset_buffer, true);

            if 0 != nwritten {
                Some(&self.charset_buffer[..nwritten])
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::Read;
    use std::sync::Arc;

    use super::*;
    use crate::mime::fetch::section::*;
    use crate::mime::grovel;

    fn fetch_bytes(
        message: &[u8],
        decode_charset: bool,
        subscripts: Vec<u32>,
    ) -> Vec<u8> {
        let (_, result) = grovel::grovel(
            &mut grovel::SimpleAccessor {
                data: message.into(),
                ..grovel::SimpleAccessor::default()
            },
            BodySection {
                subscripts,
                leaf_type: LeafType::Content,
                // This causes it to use ContentDecoder
                decode_cte: true,
                decode_charset,
                ..BodySection::default()
            }
            .fetcher(Arc::new(CommonPaths {
                tmp: std::env::temp_dir(),
                garbage: std::env::temp_dir(),
            })),
        )
        .unwrap();
        let mut result = result.unwrap();

        let mut ret = Vec::new();
        result.buffer.read_to_end(&mut ret).unwrap();
        ret
    }

    #[test]
    fn decode_untransformed() {
        let fetched = fetch_bytes(
            b"Content-Type: text/plain\r\n\
              \r\n\
              foo\xFE",
            false,
            vec![],
        );
        assert_eq!(b"foo\xFE", &fetched[..]);
        let fetched = fetch_bytes(
            b"Content-Type: text/plain\r\n\
              Content-Transfer-Encoding: 7BIT\r\n\
              \r\n\
              foo\xFE",
            false,
            vec![],
        );
        assert_eq!(b"foo\xFE", &fetched[..]);
        let fetched = fetch_bytes(
            b"Content-Type: text/plain\r\n\
              Content-Transfer-Encoding: 8BIT\r\n\
              \r\n\
              foo\xFE",
            false,
            vec![],
        );
        assert_eq!(b"foo\xFE", &fetched[..]);
        let fetched = fetch_bytes(
            b"Content-Type: text/plain\r\n\
              Content-Transfer-Encoding: BINARY\r\n\
              \r\n\
              foo\xFE",
            false,
            vec![],
        );
        assert_eq!(b"foo\xFE", &fetched[..]);
    }

    #[test]
    fn decode_base64_binary() {
        let fetched = fetch_bytes(
            b"Content-Type: text/plain; charset=\"ISO-8859-1\"\r\n\
              Content-Transfer-Encoding: Base64\r\n\
              \r\n\
              V\r\n\
              Gh\n\
              hdC\n\
              Bpcy\n\
              Bub3QgZ\n\
              GVhZCB3aGl\n\
              jaCBjYW4gZXRl\n\
              cm5hbCBsaWUuXG5Bbm\n\
              Qgd2l0aCBzdHJhbmdlIOZvb\n\
              nMgZXZlbiBkZWF0aCBtYXkgZGllLg==\r\n",
            false,
            vec![],
        );
        assert_eq!(
            b"That is not dead which can eternal lie.\\n\
              And with strange \xE6ons even death may die."
                as &[u8],
            &fetched[..]
        );

        // Multiparts have content pushed in a different pattern, so test that
        // too
        let fetched = fetch_bytes(
            b"Content-Type: multipart/mixed; boundary=bound\r\n\
              \r\n\
              --bound\r\n\
              Content-Type: text/plain; charset=\"ISO-8859-1\"\r\n\
              Content-Transfer-Encoding: Base64\r\n\
              \r\n\
              V\r\n\
              Gh\n\
              hdC\n\
              Bpcy\n\
              Bub3QgZ\n\
              GVhZCB3aGl\n\
              jaCBjYW4gZXRl\n\
              cm5hbCBsaWUuXG5Bbm\n\
              Qgd2l0aCBzdHJhbmdlIOZvb\n\
              nMgZXZlbiBkZWF0aCBtYXkgZGllLg==\r\n\
              \r\n\
              --bound\r\n",
            false,
            vec![1],
        );
        assert_eq!(
            b"That is not dead which can eternal lie.\\n\
              And with strange \xE6ons even death may die."
                as &[u8],
            &fetched[..]
        );
    }

    #[test]
    fn decode_qp_binary() {
        let fetched = fetch_bytes(
            b"Content-Type: text/plain; charset=\"ISO-8859-1\"\r\n\
              Content-Transfer-Encoding: quoted-printable\r\n\
              \r\n\
              That is not dead =\n\
              which can eternal lie.=0A=\r\n\
              And with strange =E6ons =\n\
              even death may die.=",
            false,
            vec![],
        );
        assert_eq!(
            b"That is not dead which can eternal lie.\n\
              And with strange \xE6ons even death may die."
                as &[u8],
            &fetched[..]
        );

        let fetched = fetch_bytes(
            b"Content-Type: multipart/mixed; boundary=bound\r\n\
              \r\n\
              --bound\r\n\
              Content-Type: text/plain; charset=\"ISO-8859-1\"\r\n\
              Content-Transfer-Encoding: quoted-printable\r\n\
              \r\n\
              That is not dead =\n\
              which can eternal lie.=0A=\r\n\
              And with strange =E6ons =\n\
              even death may die.=\r\n\
              --bound",
            false,
            vec![1],
        );
        assert_eq!(
            b"That is not dead which can eternal lie.\n\
              And with strange \xE6ons even death may die."
                as &[u8],
            &fetched[..],
            "Unexpected result: {:?}",
            String::from_utf8_lossy(&fetched)
        );
    }

    #[test]
    fn decode_qp_iso8859_1() {
        let fetched = fetch_bytes(
            b"Content-Type: text/plain; charset=\"ISO-8859-1\"\r\n\
              Content-Transfer-Encoding: quoted-printable\r\n\
              \r\n\
              That is not dead =\n\
              which can eternal lie.=0A=\r\n\
              And with strange =E6ons =\n\
              even death may die.=",
            true,
            vec![],
        );
        assert_eq!(
            b"That is not dead which can eternal lie.\n\
              And with strange \xC3\xA6ons even death may die."
                as &[u8],
            &fetched[..]
        );
    }

    #[test]
    fn decode_base64_iso8859_1() {
        let fetched = fetch_bytes(
            b"Content-Type: text/plain; charset=\"ISO-8859-1\"\r\n\
              Content-Transfer-Encoding: Base64\r\n\
              \r\n\
              V\r\n\
              Gh\n\
              hdC\n\
              Bpcy\n\
              Bub3QgZ\n\
              GVhZCB3aGl\n\
              jaCBjYW4gZXRl\n\
              cm5hbCBsaWUuXG5Bbm\n\
              Qgd2l0aCBzdHJhbmdlIOZvb\n\
              nMgZXZlbiBkZWF0aCBtYXkgZGllLg==\r\n",
            true,
            vec![],
        );
        assert_eq!(
            b"That is not dead which can eternal lie.\\n\
              And with strange \xC3\xA6ons even death may die."
                as &[u8],
            &fetched[..]
        );
    }

    #[test]
    fn decode_base64_shiftjis() {
        let fetched = fetch_bytes(
            b"Content-Type: text/plain; charset=\"SHIFT-JIS\"\r\n\
              Content-Transfer-Encoding: Base64\r\n\
              \r\n\
              iOqPj4LJiOqU1IuWgrOC6oLIgqKCsYLGgvCCtYLmgqQ=\r\n",
            true,
            vec![],
        );
        assert_eq!("一緒に一番許されないことをしよう".as_bytes(), &fetched[..]);
    }

    #[test]
    fn decode_8bit_shiftjis() {
        let fetched = fetch_bytes(
            b"Content-Type: text/plain; charset=\"SHIFT-JIS\"\r\n\
              Content-Transfer-Encoding: 8bit\r\n\
              \r\n\
              \x88\xea\x8f\x8f\x82\xc9\x88\xea\
              \x94\xd4\x8b\x96\x82\xb3\x82\xea\
              \x82\xc8\x82\xa2\x82\xb1\x82\xc6\
              \x82\xf0\x82\xb5\x82\xe6\x82\xa4\r\n",
            true,
            vec![],
        );
        assert_eq!(
            "一緒に一番許されないことをしよう\r\n".as_bytes(),
            &fetched[..]
        );
    }

    #[test]
    fn decode_7bit_utf7() {
        let fetched = fetch_bytes(
            b"Content-Type: text/plain; charset=\"UTF-7\"\r\n\
              \r\n\
              That is not dead which can eternal lie.\r\n\
              And with strange +AOY-ons even death may die.\r\n",
            true,
            vec![],
        );
        assert_eq!(
            b"That is not dead which can eternal lie.\r\n\
              And with strange \xC3\xA6ons even death may die.\r\n"
                as &[u8],
            &fetched[..],
            "Unexpected result: {:?}",
            String::from_utf8_lossy(&fetched)
        );
    }

    #[test]
    fn no_charset_conversion_on_non_text_part() {
        let fetched = fetch_bytes(
            b"Content-Type: application/octet-stream; charset=\"UTF-7\"\r\n\
              \r\n\
              That is not dead which can eternal lie.\r\n\
              And with strange +AOY-ons even death may die.\r\n",
            true,
            vec![],
        );
        assert_eq!(
            b"That is not dead which can eternal lie.\r\n\
              And with strange +AOY-ons even death may die.\r\n"
                as &[u8],
            &fetched[..],
            "Unexpected result: {:?}",
            String::from_utf8_lossy(&fetched)
        );
    }
}
