//! The control stream from `ssai run` to the host process it starts as the
//! sandbox account (`ssai __sandbox-host`): the host's standard input carries
//! frames, so keystrokes, a terminal resize, Ctrl-C and the end of input
//! travel on one pipe. Pure, so it is tested on every host.

// Off Windows this module is compiled for its tests only; on Windows the
// host reads frames, and the writer half is the launcher's.
#![allow(dead_code)]

use std::io::{self, Read, Write};

/// The largest payload one frame carries; longer input is split.
pub const MAX_PAYLOAD: usize = 64 * 1024;

/// One message to the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Bytes for the client's input.
    Data(Vec<u8>),
    /// The terminal now has this many columns and rows.
    Resize { cols: u16, rows: u16 },
    /// The user pressed Ctrl-C (a run without a terminal relay, where the
    /// key reaches `ssai` rather than the client).
    Interrupt,
    /// No more input: the client's input is closed.
    Eof,
}

const DATA: u8 = 0;
const RESIZE: u8 = 1;
const INTERRUPT: u8 = 2;
const EOF: u8 = 3;

impl Frame {
    /// Write the frame: a kind byte, a little-endian `u32` length, the payload.
    pub fn write_to(&self, out: &mut impl Write) -> io::Result<()> {
        let (kind, payload): (u8, Vec<u8>) = match self {
            Frame::Data(bytes) => (DATA, bytes.clone()),
            Frame::Resize { cols, rows } => (RESIZE, [cols.to_le_bytes(), rows.to_le_bytes()].concat()),
            Frame::Interrupt => (INTERRUPT, Vec::new()),
            Frame::Eof => (EOF, Vec::new()),
        };
        if payload.len() > MAX_PAYLOAD {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame payload too large"));
        }
        let mut buf = Vec::with_capacity(5 + payload.len());
        buf.push(kind);
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&payload);
        out.write_all(&buf)?;
        out.flush()
    }

    /// Read the next frame; `None` at the end of the stream. A malformed
    /// frame (an unknown kind, an oversized or misshapen payload) is an error.
    pub fn read_from(input: &mut impl Read) -> io::Result<Option<Frame>> {
        let mut head = [0u8; 5];
        match input.read_exact(&mut head) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let len = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
        if len > MAX_PAYLOAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame payload too large"));
        }
        let mut payload = vec![0u8; len];
        input.read_exact(&mut payload)?;
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "malformed frame");
        Ok(Some(match head[0] {
            DATA => Frame::Data(payload),
            RESIZE if len == 4 => Frame::Resize {
                cols: u16::from_le_bytes([payload[0], payload[1]]),
                rows: u16::from_le_bytes([payload[2], payload[3]]),
            },
            INTERRUPT if len == 0 => Frame::Interrupt,
            EOF if len == 0 => Frame::Eof,
            _ => return Err(bad()),
        }))
    }
}

/// Write `bytes` as as many [`Frame::Data`] frames as they need.
pub fn write_data(out: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    for chunk in bytes.chunks(MAX_PAYLOAD) {
        Frame::Data(chunk.to_vec()).write_to(out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_frame_reads_back_as_written_and_the_stream_ends_cleanly() {
        let frames = [
            Frame::Data(b"hello\x03".to_vec()),
            Frame::Data(Vec::new()),
            Frame::Resize { cols: 120, rows: 40 },
            Frame::Resize { cols: u16::MAX, rows: 0 },
            Frame::Interrupt,
            Frame::Eof,
        ];
        let mut buf = Vec::new();
        for f in &frames {
            f.write_to(&mut buf).unwrap();
        }
        let mut input = buf.as_slice();
        for f in &frames {
            assert_eq!(Frame::read_from(&mut input).unwrap().as_ref(), Some(f));
        }
        assert_eq!(Frame::read_from(&mut input).unwrap(), None);
    }

    #[test]
    fn long_input_is_split_at_the_payload_cap() {
        let bytes = vec![7u8; MAX_PAYLOAD * 2 + 1];
        let mut buf = Vec::new();
        write_data(&mut buf, &bytes).unwrap();
        let mut input = buf.as_slice();
        let mut back = Vec::new();
        let mut sizes = Vec::new();
        while let Some(Frame::Data(d)) = Frame::read_from(&mut input).unwrap() {
            sizes.push(d.len());
            back.extend(d);
        }
        assert_eq!(sizes, [MAX_PAYLOAD, MAX_PAYLOAD, 1]);
        assert_eq!(back, bytes);
    }

    #[test]
    fn a_malformed_frame_is_refused() {
        let cases: [&[u8]; 5] = [
            &[9, 0, 0, 0, 0],                                  // unknown kind
            &[RESIZE, 3, 0, 0, 0, 1, 2, 3],                    // resize of 3 bytes
            &[INTERRUPT, 1, 0, 0, 0, 0],                       // interrupt with a payload
            &[DATA, 0xff, 0xff, 0xff, 0x7f],                   // over the cap
            &[DATA, 4, 0, 0, 0, 1, 2],                         // cut short
        ];
        for case in cases {
            let mut input = case;
            assert!(Frame::read_from(&mut input).is_err(), "{case:?}");
        }
        // A header cut short is the end of the stream, not an error.
        let mut input: &[u8] = &[DATA, 1];
        assert_eq!(Frame::read_from(&mut input).unwrap(), None);
    }

    #[test]
    fn an_oversized_frame_is_never_written() {
        let mut buf = Vec::new();
        assert!(Frame::Data(vec![0; MAX_PAYLOAD + 1]).write_to(&mut buf).is_err());
        assert!(buf.is_empty());
    }
}
