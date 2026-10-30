//! Record-aware I/O for a socket with Linux kTLS already installed.
//!
//! Application plaintext goes directly into the caller's initialized, unfilled
//! `ReadBuf`; control bytes never advance its filled length. There is no staging
//! buffer or heap allocation on successful reads (only two saved alert bytes).
//! The kernel guarantees that one `recvmsg` never mixes TLS record types.
//!
//! All handshake controls, including TLS 1.3 `NewSessionTicket` and `KeyUpdate`,
//! are deliberately unsupported and terminal. This module does not parse
//! handshakes, process tickets, or update keys. Only `close_notify` is accepted
//! as an alert. Empty application records are skipped; empty controls and
//! unexpected ancillary messages fail closed.
//! Do not use these helpers before installing kTLS or interleave other readers
//! with `RecordReader`: its partial-alert and terminal state belongs to one
//! connection for the rest of that connection's lifetime.

#![cfg(target_os = "linux")]

use std::io;
use std::mem::{self, size_of};
use std::os::fd::AsRawFd as _;
use std::task::{Context, Poll};

use tokio::io::{Interest, ReadBuf};
use tokio::net::TcpStream;

// Linux UAPI <linux/tls.h>; these cmsg types are not exported by libc.
const TLS_SET_RECORD_TYPE: libc::c_int = 1;
const TLS_GET_RECORD_TYPE: libc::c_int = 2;
const ALERT: u8 = 21;
const HANDSHAKE: u8 = 22;
const APPLICATION_DATA: u8 = 23;
const CLOSE_NOTIFY: [u8; 2] = [1, 0];

// Also bound EINTR and spurious-readiness retries, not just consumed controls.
const IO_BUDGET: usize = 32;

// SAFETY: CMSG_LEN/SPACE only perform size arithmetic; one byte cannot overflow.
const CONTROL_LEN: usize = unsafe { libc::CMSG_LEN(1) as usize };
// SAFETY: As above, including the platform's ancillary padding.
const CONTROL_SPACE: usize = unsafe { libc::CMSG_SPACE(1) as usize };

/// One aligned ancillary header and a padded one-byte record type. Use libc's
/// actual header layout, including on targets where its length is not usize.
#[repr(C)]
struct Control {
    header: libc::cmsghdr,
    payload: [u8; size_of::<usize>()],
}

// These prove that typed access to payload[0] agrees with CMSG_DATA, and that
// passing CONTROL_SPACE bytes never runs beyond the allocation.
const _: () = {
    // SAFETY: Zero-length CMSG_LEN only computes the aligned header size.
    assert!(mem::offset_of!(Control, payload) == unsafe { libc::CMSG_LEN(0) as usize });
    assert!(mem::offset_of!(Control, payload) == size_of::<libc::cmsghdr>());
    assert!(size_of::<Control>() == CONTROL_SPACE);
};

impl Control {
    fn new() -> Self {
        // SAFETY: cmsghdr contains integer fields only; zero is valid for them
        // and the byte array. Initialize padding as well as the payload.
        unsafe { mem::zeroed() }
    }

    fn message(&mut self, iov: &mut libc::iovec) -> libc::msghdr {
        // SAFETY: All-zero msghdr has valid null pointers and integer fields.
        // The two nonempty buffers are installed below and outlive the syscall.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        msg.msg_control = std::ptr::from_mut(self).cast();
        // The length is one tiny cmsg on every Linux ABI, including those with
        // a 32-bit msg_controllen on a 64-bit target.
        #[allow(clippy::cast_possible_truncation)]
        {
            msg.msg_controllen = CONTROL_SPACE as _;
        }
        msg
    }

    fn set_record_type(&mut self, record_type: u8) {
        #[allow(clippy::cast_possible_truncation)]
        {
            self.header.cmsg_len = CONTROL_LEN as _;
        }
        self.header.cmsg_level = libc::SOL_TLS;
        self.header.cmsg_type = TLS_SET_RECORD_TYPE;
        self.payload[0] = record_type;
    }

    // cmsg_len is usize on glibc, but not on every supported Linux libc.
    #[allow(clippy::unnecessary_cast)]
    fn record_type(&self, len: usize, flags: libc::c_int) -> io::Result<Option<u8>> {
        if flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
            return Err(invalid_data(
                "truncated kTLS recvmsg payload or ancillary data",
            ));
        }
        if len == 0 {
            // Kernel documentation permits application data without a type cmsg.
            return Ok(None);
        }
        // The buffer has room for exactly one one-byte type cmsg. Reject short
        // headers, wrong payload sizes, extra messages and unrelated ancillary
        // data instead of guessing that their payload is application data.
        if !(CONTROL_LEN..=CONTROL_SPACE).contains(&len)
            || self.header.cmsg_len as usize != CONTROL_LEN
            || self.header.cmsg_level != libc::SOL_TLS
            || self.header.cmsg_type != TLS_GET_RECORD_TYPE
        {
            return Err(invalid_data("invalid kTLS record-type ancillary message"));
        }
        Ok(Some(self.payload[0]))
    }
}

/// Older kernels can report application data once for queued plaintext and
/// again for a newly decrypted record in the same recvmsg.
#[repr(transparent)]
struct RecvControl([Control; 2]);

impl RecvControl {
    fn new() -> Self {
        Self([Control::new(), Control::new()])
    }

    fn message(&mut self, iov: &mut libc::iovec) -> libc::msghdr {
        let mut msg = self.0[0].message(iov);
        msg.msg_control = self.0.as_mut_ptr().cast();
        #[allow(clippy::cast_possible_truncation)]
        {
            msg.msg_controllen = size_of::<Self>() as _;
        }
        msg
    }

    fn record_type(&self, len: usize, flags: libc::c_int) -> io::Result<Option<u8>> {
        let first = self.0[0].record_type(len.min(CONTROL_SPACE), flags)?;
        if len <= CONTROL_SPACE {
            return Ok(first);
        }
        let second = self.0[1].record_type(len - CONTROL_SPACE, flags)?;
        if first != Some(APPLICATION_DATA) || second != first {
            return Err(invalid_data(
                "conflicting or unsupported duplicate kTLS record-type messages",
            ));
        }
        Ok(first)
    }
}

struct Received {
    len: usize,
    record_type: Option<u8>,
    flags: libc::c_int,
}

fn recv_record(tcp: &TcpStream, dst: &mut [u8]) -> io::Result<Received> {
    let mut control = RecvControl::new();
    let mut iov = libc::iovec {
        iov_base: dst.as_mut_ptr().cast(),
        iov_len: dst.len(),
    };
    let mut msg = control.message(&mut iov);
    // SAFETY: tcp owns a live fd; dst is initialized writable memory. msg, iov,
    // and the aligned control buffer remain live and exclusive until return.
    // MSG_DONTWAIT makes this nonblocking even independently of O_NONBLOCK.
    let n = unsafe { libc::recvmsg(tcp.as_raw_fd(), &raw mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::cast_sign_loss)]
    let len = n as usize;
    // msg_controllen differs between Linux libc ABIs.
    #[allow(clippy::unnecessary_cast)]
    let record_type = control
        .record_type(msg.msg_controllen as usize, msg.msg_flags)
        .map_err(|error| recv_error(&error, &msg, &control, len, dst.len()))?;
    if len > dst.len() {
        return Err(recv_error(
            &invalid_data("kTLS recvmsg exceeded its destination buffer"),
            &msg,
            &control,
            len,
            dst.len(),
        ));
    }
    Ok(Received {
        len,
        record_type,
        flags: msg.msg_flags,
    })
}

#[allow(clippy::unnecessary_cast)]
fn recv_error(
    error: &io::Error,
    msg: &libc::msghdr,
    control: &RecvControl,
    received: usize,
    capacity: usize,
) -> io::Error {
    let first = &control.0[0];
    let first_record_type = first
        .record_type((msg.msg_controllen as usize).min(CONTROL_SPACE), 0)
        .ok()
        .flatten();
    io::Error::new(
        error.kind(),
        format!(
            "{error} (recvmsg: msg_flags={:#x}, MSG_CTRUNC={}, MSG_TRUNC={}, MSG_EOR={}, \
             received={received}, capacity={capacity}, msg_controllen={}, control_capacity={}, \
             cmsg_len={}, cmsg_level={}, cmsg_type={}, first_record_type={first_record_type:?})",
            msg.msg_flags,
            msg.msg_flags & libc::MSG_CTRUNC != 0,
            msg.msg_flags & libc::MSG_TRUNC != 0,
            msg.msg_flags & libc::MSG_EOR != 0,
            msg.msg_controllen,
            size_of::<RecvControl>(),
            first.header.cmsg_len,
            first.header.cmsg_level,
            first.header.cmsg_type,
        ),
    )
}

enum Terminal {
    Closed,
    Failed(io::Error),
}

#[derive(Debug, Eq, PartialEq)]
enum ReadOutcome {
    Data(usize),
    More,
    Eof,
}

/// Per-connection receive state, retained across polls and cancelled reads.
/// A bare TCP FIN is a sticky `UnexpectedEof`, never an authenticated TLS EOF.
#[derive(Default)]
pub(crate) struct RecordReader {
    alert: [u8; 2],
    alert_len: usize,
    terminal: Option<Terminal>,
}

impl RecordReader {
    pub(crate) fn poll_read(
        &mut self,
        tcp: &TcpStream,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(result) = self.finished() {
            return Poll::Ready(result.map(|_| ()));
        }
        if buf.remaining() == 0 {
            // A zero-capacity read must not be mistaken for transport EOF.
            return Poll::Ready(Ok(()));
        }

        for _ in 0..IO_BUDGET {
            let dst = buf.initialize_unfilled();
            match tcp.try_io(Interest::READABLE, || recv_record(tcp, dst)) {
                Ok(record) => {
                    match self.consume(record.record_type, record.flags, &dst[..record.len]) {
                        Ok(ReadOutcome::Data(n)) => {
                            buf.advance(n);
                            return Poll::Ready(Ok(()));
                        }
                        Ok(ReadOutcome::Eof) => return Poll::Ready(Ok(())),
                        Ok(ReadOutcome::More) => {}
                        Err(error) => return Poll::Ready(Err(error)),
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    // try_io clears READABLE only after the raw syscall really
                    // would block; this poll then registers the current waker.
                    match tcp.poll_read_ready(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(self.fail(error))),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                Err(error) => return Poll::Ready(Err(self.fail(error))),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn finished(&self) -> Option<io::Result<ReadOutcome>> {
        match &self.terminal {
            None => None,
            Some(Terminal::Closed) => Some(Ok(ReadOutcome::Eof)),
            Some(Terminal::Failed(error)) => Some(Err(copy_error(error))),
        }
    }

    fn fail(&mut self, error: io::Error) -> io::Error {
        // Keep the original error (including errno/source) for the first return.
        // Subsequent reads reproduce errno, or the original kind and message.
        self.terminal = Some(Terminal::Failed(copy_error(&error)));
        error
    }

    fn reject(&mut self, message: &'static str) -> io::Error {
        self.fail(invalid_data(message))
    }

    fn consume(
        &mut self,
        record_type: Option<u8>,
        flags: libc::c_int,
        payload: &[u8],
    ) -> io::Result<ReadOutcome> {
        if let Some(result) = self.finished() {
            return result;
        }
        if flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
            return Err(self.reject("truncated kTLS recvmsg payload or ancillary data"));
        }
        if payload.is_empty() {
            if record_type == Some(APPLICATION_DATA) && self.alert_len == 0 {
                // Empty application records are legal TLS padding/traffic
                // shaping. Metadata distinguishes them from a bare TCP FIN.
                return Ok(ReadOutcome::More);
            }
            if record_type.is_some() || flags & libc::MSG_EOR != 0 {
                return Err(self.reject("empty kTLS record is unsupported"));
            }
            return Err(self.fail(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "kTLS peer closed without close_notify",
            )));
        }
        let record_type = record_type.unwrap_or(APPLICATION_DATA);
        if self.alert_len != 0 && record_type != ALERT {
            return Err(self.reject("kTLS alert interrupted by another record type"));
        }
        match record_type {
            APPLICATION_DATA => Ok(ReadOutcome::Data(payload.len())),
            ALERT => self.consume_alert(flags, payload),
            HANDSHAKE => Err(self.fail(io::Error::new(
                io::ErrorKind::Unsupported,
                "kTLS handshake controls (including NewSessionTicket and KeyUpdate) are unsupported",
            ))),
            _ => Err(self.reject("unsupported kTLS record type")),
        }
    }

    fn consume_alert(&mut self, flags: libc::c_int, payload: &[u8]) -> io::Result<ReadOutcome> {
        if payload.len() > self.alert.len() - self.alert_len {
            return Err(self.reject("oversized kTLS alert"));
        }
        let end = self.alert_len + payload.len();
        self.alert[self.alert_len..end].copy_from_slice(payload);
        self.alert_len = end;

        if flags & libc::MSG_EOR == 0 {
            if self.alert_len == self.alert.len() {
                // Do not accept a close prefix of a longer/malformed record.
                return Err(self.reject("kTLS alert exceeds two bytes without end-of-record"));
            }
            // Only one byte can be held here. Never return an empty successful
            // read while waiting for the second byte: that would look like EOF.
            return Ok(ReadOutcome::More);
        }
        if self.alert_len != self.alert.len() {
            return Err(self.reject("truncated kTLS alert at end-of-record"));
        }
        // RFC 5246 permits close_notify at warning level; RFC 8446 treats the
        // description as decisive regardless of the legacy alert level. Accept
        // either defined level (1 or 2), without needing the negotiated version.
        if matches!(self.alert[0], 1 | 2) && self.alert[1] == 0 {
            self.terminal = Some(Terminal::Closed);
            Ok(ReadOutcome::Eof)
        } else {
            Err(self.reject("invalid or non-close kTLS alert"))
        }
    }
}

/// Send one encrypted `close_notify` using the installed kTLS TX keys.
///
/// The caller must latch both success and any returned error: do not call again
/// after either, and do not allow further application writes. In particular a
/// partial send is terminal, not a request to resend the alert or its tail.
/// `Pending` is safe to retry; no alert bytes have been accepted in that case.
/// This does not shut down TCP or wait for the peer's reciprocal `close_notify`.
pub(crate) fn poll_close_notify(tcp: &TcpStream, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    for _ in 0..IO_BUDGET {
        match tcp.try_io(Interest::WRITABLE, || send_close_notify(tcp)) {
            Ok(()) => return Poll::Ready(Ok(())),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                match tcp.poll_write_ready(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            Err(error) => return Poll::Ready(Err(error)),
        }
    }
    cx.waker().wake_by_ref();
    Poll::Pending
}

fn send_close_notify(tcp: &TcpStream) -> io::Result<()> {
    let mut control = Control::new();
    control.set_record_type(ALERT);
    let mut iov = libc::iovec {
        // sendmsg reads iov_base; libc uses a mutable pointer for both directions.
        iov_base: CLOSE_NOTIFY.as_ptr().cast_mut().cast(),
        iov_len: CLOSE_NOTIFY.len(),
    };
    let msg = control.message(&mut iov);
    // SAFETY: tcp owns a live fd; the iovec points to two live readable bytes,
    // and msg/control are initialized, aligned, and live through the syscall.
    // No MSG_MORE: this alert must end its record. The kernel encrypts plaintext.
    let n = unsafe {
        libc::sendmsg(
            tcp.as_raw_fd(),
            &raw const msg,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::cast_sign_loss)]
    let sent = n as usize;
    check_close_notify_write(sent)
}

fn check_close_notify_write(sent: usize) -> io::Result<()> {
    match sent {
        2 => Ok(()),
        0 => Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "kTLS close_notify send made no progress",
        )),
        _ => Err(invalid_data(
            "partial or invalid kTLS close_notify send; connection cannot be reused",
        )),
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn copy_error(error: &io::Error) -> io::Error {
    match error.raw_os_error() {
        Some(errno) => io::Error::from_raw_os_error(errno),
        None => io::Error::new(error.kind(), error.to_string()),
    }
}

#[cfg(test)]
// The same layout tests also cover Linux libcs with non-usize cmsg lengths.
#[allow(clippy::unnecessary_cast)]
mod tests {
    use super::*;

    fn rx_control(record_type: u8) -> Control {
        let mut control = Control::new();
        control.set_record_type(record_type);
        control.header.cmsg_type = TLS_GET_RECORD_TYPE;
        control
    }

    fn assert_sticky_error(reader: &mut RecordReader, first: &io::Error) {
        // No later application bytes may become visible after a bad control.
        let later = reader
            .consume(Some(APPLICATION_DATA), libc::MSG_EOR, b"hidden")
            .unwrap_err();
        assert_eq!(later.kind(), first.kind());
        assert_eq!(later.to_string(), first.to_string());
        assert_eq!(later.raw_os_error(), first.raw_os_error());
    }

    #[test]
    fn ancillary_storage_matches_libc_macros() {
        let mut control = Control::new();
        control.set_record_type(ALERT);
        let mut bytes = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        let msg = control.message(&mut iov);
        assert_eq!(msg.msg_controllen as usize, CONTROL_SPACE);
        assert!(mem::align_of::<Control>() >= mem::align_of::<libc::cmsghdr>());
        // SAFETY: msg points to the live, aligned Control, whose initialized
        // header describes one byte within its actual allocation.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&raw const msg);
            assert_eq!(header, &raw mut control.header);
            assert_eq!((*header).cmsg_level, libc::SOL_TLS);
            assert_eq!((*header).cmsg_type, TLS_SET_RECORD_TYPE);
            assert_eq!((*header).cmsg_len as usize, CONTROL_LEN);
            assert_eq!(*libc::CMSG_DATA(header), ALERT);
            assert!(libc::CMSG_NXTHDR(&raw const msg, header).is_null());
        }
    }

    #[test]
    fn ancillary_missing_or_valid_record_type() {
        assert_eq!(Control::new().record_type(0, 0).unwrap(), None);
        for kind in [ALERT, HANDSHAKE, APPLICATION_DATA, 255] {
            for len in CONTROL_LEN..=CONTROL_SPACE {
                assert_eq!(rx_control(kind).record_type(len, 0).unwrap(), Some(kind));
            }
        }
    }

    #[test]
    fn receive_ancillary_storage_holds_two_aligned_messages() {
        let mut control = RecvControl([rx_control(APPLICATION_DATA), rx_control(APPLICATION_DATA)]);
        let mut bytes = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        let msg = control.message(&mut iov);
        assert_eq!(msg.msg_controllen as usize, 2 * CONTROL_SPACE);
        assert_eq!(size_of::<RecvControl>(), 2 * CONTROL_SPACE);
        // SAFETY: Both headers describe initialized, aligned one-byte messages
        // within the live control array, and msg covers exactly that array.
        unsafe {
            let first = libc::CMSG_FIRSTHDR(&raw const msg);
            assert_eq!(first, &raw mut control.0[0].header);
            let second = libc::CMSG_NXTHDR(&raw const msg, first);
            assert_eq!(second, &raw mut control.0[1].header);
            assert_eq!(*libc::CMSG_DATA(first), APPLICATION_DATA);
            assert_eq!(*libc::CMSG_DATA(second), APPLICATION_DATA);
            assert!(libc::CMSG_NXTHDR(&raw const msg, second).is_null());
        }
    }

    #[test]
    fn receive_ancillary_accepts_missing_single_and_duplicate_application_types() {
        assert_eq!(RecvControl::new().record_type(0, 0).unwrap(), None);
        for kind in [ALERT, HANDSHAKE, APPLICATION_DATA, 255] {
            let control = RecvControl([rx_control(kind), Control::new()]);
            for len in CONTROL_LEN..=CONTROL_SPACE {
                assert_eq!(control.record_type(len, 0).unwrap(), Some(kind));
            }
        }
        let control = RecvControl([rx_control(APPLICATION_DATA), rx_control(APPLICATION_DATA)]);
        for len in CONTROL_SPACE + CONTROL_LEN..=2 * CONTROL_SPACE {
            for flags in [0, libc::MSG_EOR] {
                let kind = control.record_type(len, flags).unwrap();
                let mut reader = RecordReader::default();
                assert_eq!(
                    reader.consume(kind, flags, b"upload").unwrap(),
                    ReadOutcome::Data(6)
                );
            }
        }
    }

    #[test]
    fn receive_ancillary_rejects_conflicting_or_duplicate_control_types() {
        for first in [ALERT, HANDSHAKE, APPLICATION_DATA, 255] {
            for second in [ALERT, HANDSHAKE, APPLICATION_DATA, 255] {
                if first == APPLICATION_DATA && second == APPLICATION_DATA {
                    continue;
                }
                let control = RecvControl([rx_control(first), rx_control(second)]);
                let error = control.record_type(2 * CONTROL_SPACE, 0).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                let mut reader = RecordReader::default();
                let first = reader.fail(error);
                assert_sticky_error(&mut reader, &first);
            }
        }
    }

    #[test]
    fn receive_ancillary_rejects_incomplete_malformed_or_truncated_messages() {
        let mut control = RecvControl([rx_control(APPLICATION_DATA), rx_control(APPLICATION_DATA)]);
        for len in (1..CONTROL_LEN)
            .chain(CONTROL_SPACE + 1..CONTROL_SPACE + CONTROL_LEN)
            .chain([2 * CONTROL_SPACE + 1, usize::MAX])
        {
            assert!(control.record_type(len, 0).is_err());
        }
        for flags in [libc::MSG_CTRUNC, libc::MSG_TRUNC] {
            for len in [0, CONTROL_SPACE, 2 * CONTROL_SPACE] {
                let error = control.record_type(len, flags).unwrap_err();
                let mut reader = RecordReader::default();
                let first = reader.fail(error);
                assert_sticky_error(&mut reader, &first);
            }
        }
        for index in 0..2 {
            for len in [0, CONTROL_LEN - 1, CONTROL_LEN + 1, usize::MAX] {
                #[allow(clippy::cast_possible_truncation)]
                {
                    control.0[index].header.cmsg_len = len as _;
                }
                assert!(control.record_type(2 * CONTROL_SPACE, 0).is_err());
            }
            control.0[index] = rx_control(APPLICATION_DATA);
            control.0[index].header.cmsg_level = libc::SOL_SOCKET;
            assert!(control.record_type(2 * CONTROL_SPACE, 0).is_err());
            control.0[index] = rx_control(APPLICATION_DATA);
            control.0[index].header.cmsg_type = TLS_SET_RECORD_TYPE;
            assert!(control.record_type(2 * CONTROL_SPACE, 0).is_err());
            control.0[index] = rx_control(APPLICATION_DATA);
        }
    }

    #[test]
    fn ancillary_rejects_malformed_lengths_and_unrelated_headers() {
        let mut control = rx_control(ALERT);
        for len in (1..CONTROL_LEN).chain([CONTROL_SPACE + 1, usize::MAX]) {
            assert!(control.record_type(len, 0).is_err());
        }
        for len in [0, CONTROL_LEN - 1, CONTROL_LEN + 1, CONTROL_SPACE + 1] {
            #[allow(clippy::cast_possible_truncation)]
            {
                control.header.cmsg_len = len as _;
            }
            assert!(control.record_type(CONTROL_SPACE, 0).is_err());
        }
        control = rx_control(ALERT);
        control.header.cmsg_level = libc::SOL_SOCKET;
        assert!(control.record_type(CONTROL_SPACE, 0).is_err());
        control = rx_control(ALERT);
        control.header.cmsg_type = TLS_SET_RECORD_TYPE;
        assert!(control.record_type(CONTROL_SPACE, 0).is_err());
    }

    #[test]
    fn truncated_ancillary_or_payload_is_terminal() {
        for flags in [libc::MSG_CTRUNC, libc::MSG_TRUNC] {
            for len in [0, CONTROL_SPACE] {
                let error = rx_control(ALERT).record_type(len, flags).unwrap_err();
                let mut reader = RecordReader::default();
                let first = reader.fail(error);
                assert_sticky_error(&mut reader, &first);
            }
            let mut reader = RecordReader::default();
            let first = reader
                .consume(Some(ALERT), flags | libc::MSG_EOR, &CLOSE_NOTIFY)
                .unwrap_err();
            assert_sticky_error(&mut reader, &first);
        }
    }

    #[test]
    fn receive_errors_include_flags_lengths_and_record_metadata() {
        for flags in [
            libc::MSG_CTRUNC,
            libc::MSG_TRUNC,
            libc::MSG_CTRUNC | libc::MSG_TRUNC | libc::MSG_EOR,
        ] {
            for control_len in [0, CONTROL_SPACE] {
                let mut control = RecvControl([rx_control(APPLICATION_DATA), Control::new()]);
                let mut bytes = [0u8; 8];
                let mut iov = libc::iovec {
                    iov_base: bytes.as_mut_ptr().cast(),
                    iov_len: bytes.len(),
                };
                let mut msg = control.message(&mut iov);
                msg.msg_flags = flags;
                #[allow(clippy::cast_possible_truncation)]
                {
                    msg.msg_controllen = control_len as _;
                }
                let error = control.record_type(control_len, flags).unwrap_err();
                let error = recv_error(&error, &msg, &control, 3, bytes.len());
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                let message = error.to_string();
                assert!(message.starts_with("truncated kTLS recvmsg payload or ancillary data"));
                for field in [
                    format!("msg_flags={flags:#x}"),
                    format!("MSG_CTRUNC={}", flags & libc::MSG_CTRUNC != 0),
                    format!("MSG_TRUNC={}", flags & libc::MSG_TRUNC != 0),
                    format!("MSG_EOR={}", flags & libc::MSG_EOR != 0),
                    "received=3, capacity=8".to_owned(),
                    format!("msg_controllen={control_len}"),
                    format!("control_capacity={}", size_of::<RecvControl>()),
                    format!("cmsg_len={CONTROL_LEN}"),
                    format!("cmsg_level={}", libc::SOL_TLS),
                    format!("cmsg_type={TLS_GET_RECORD_TYPE}"),
                    format!(
                        "first_record_type={:?}",
                        (control_len != 0).then_some(APPLICATION_DATA)
                    ),
                ] {
                    assert!(message.contains(&field), "missing {field}: {message}");
                }
                let mut reader = RecordReader::default();
                let first = reader.fail(error);
                assert_sticky_error(&mut reader, &first);
            }
        }
    }

    #[test]
    fn application_data_does_not_require_a_type_or_record_boundary() {
        let mut reader = RecordReader::default();
        for kind in [None, Some(APPLICATION_DATA)] {
            for flags in [0, libc::MSG_EOR] {
                assert_eq!(
                    reader.consume(kind, flags, b"x").unwrap(),
                    ReadOutcome::Data(1)
                );
                assert_eq!(
                    reader.consume(kind, flags, b"hello").unwrap(),
                    ReadOutcome::Data(5)
                );
            }
        }
    }

    #[test]
    fn close_notify_accepts_both_defined_levels_and_is_sticky() {
        for level in [1, 2] {
            let mut reader = RecordReader::default();
            assert_eq!(
                reader
                    .consume(Some(ALERT), libc::MSG_EOR, &[level, 0])
                    .unwrap(),
                ReadOutcome::Eof
            );
            for kind in [None, Some(APPLICATION_DATA), Some(HANDSHAKE)] {
                assert_eq!(
                    reader.consume(kind, 0, b"hidden").unwrap(),
                    ReadOutcome::Eof
                );
            }
            assert_eq!(reader.consume(None, 0, b"").unwrap(), ReadOutcome::Eof);
        }
    }

    #[test]
    fn close_notify_can_span_two_one_byte_reads() {
        for level in [1, 2] {
            let mut reader = RecordReader::default();
            assert_eq!(
                reader.consume(Some(ALERT), 0, &[level]).unwrap(),
                ReadOutcome::More
            );
            assert!(reader.finished().is_none());
            assert_eq!(reader.alert_len, 1);
            assert_eq!(
                reader.consume(Some(ALERT), libc::MSG_EOR, &[0]).unwrap(),
                ReadOutcome::Eof
            );
        }
    }

    #[test]
    fn close_prefix_without_record_boundary_is_not_eof() {
        for split in [false, true] {
            let mut reader = RecordReader::default();
            let payload: &[u8] = if split {
                assert_eq!(
                    reader.consume(Some(ALERT), 0, &[1]).unwrap(),
                    ReadOutcome::More
                );
                &[0]
            } else {
                &CLOSE_NOTIFY
            };
            let first = reader.consume(Some(ALERT), 0, payload).unwrap_err();
            assert_eq!(first.kind(), io::ErrorKind::InvalidData);
            assert_sticky_error(&mut reader, &first);
        }
    }

    #[test]
    fn short_oversized_and_non_close_alerts_are_terminal() {
        for payload in [
            &[][..],
            &[1],
            &[0, 0],
            &[3, 0],
            &[255, 0],
            &[1, 10],
            &[2, 40],
            &[1, 0, 0],
            &[1, 0, 1, 0],
        ] {
            let mut reader = RecordReader::default();
            let first = reader
                .consume(Some(ALERT), libc::MSG_EOR, payload)
                .unwrap_err();
            assert_eq!(first.kind(), io::ErrorKind::InvalidData);
            assert_sticky_error(&mut reader, &first);
        }
    }

    #[test]
    fn split_alert_cannot_switch_record_type_or_exceed_two_bytes() {
        for kind in [None, Some(APPLICATION_DATA), Some(HANDSHAKE), Some(20)] {
            let mut reader = RecordReader::default();
            assert_eq!(
                reader.consume(Some(ALERT), 0, &[1]).unwrap(),
                ReadOutcome::More
            );
            let first = reader.consume(kind, libc::MSG_EOR, &[0]).unwrap_err();
            assert_sticky_error(&mut reader, &first);
        }
        let mut reader = RecordReader::default();
        assert_eq!(
            reader.consume(Some(ALERT), 0, &[1]).unwrap(),
            ReadOutcome::More
        );
        let first = reader
            .consume(Some(ALERT), libc::MSG_EOR, &[0, 0])
            .unwrap_err();
        assert_sticky_error(&mut reader, &first);
    }

    #[test]
    fn bare_fin_including_mid_alert_is_sticky_unexpected_eof() {
        for partial_alert in [false, true] {
            let mut reader = RecordReader::default();
            if partial_alert {
                assert_eq!(
                    reader.consume(Some(ALERT), 0, &[1]).unwrap(),
                    ReadOutcome::More
                );
            }
            let first = reader.consume(None, 0, &[]).unwrap_err();
            assert_eq!(first.kind(), io::ErrorKind::UnexpectedEof);
            assert_sticky_error(&mut reader, &first);
        }
    }

    #[test]
    fn zero_payload_with_record_metadata_is_not_transport_eof() {
        for flags in [0, libc::MSG_EOR] {
            let mut reader = RecordReader::default();
            assert_eq!(
                reader.consume(Some(APPLICATION_DATA), flags, &[]).unwrap(),
                ReadOutcome::More
            );
            assert!(reader.finished().is_none());
        }
        for kind in [Some(ALERT), Some(HANDSHAKE)] {
            for flags in [0, libc::MSG_EOR] {
                let mut reader = RecordReader::default();
                let first = reader.consume(kind, flags, &[]).unwrap_err();
                assert_eq!(first.kind(), io::ErrorKind::InvalidData);
                assert_sticky_error(&mut reader, &first);
            }
        }
        let mut reader = RecordReader::default();
        assert_eq!(
            reader.consume(None, libc::MSG_EOR, &[]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn every_handshake_control_fails_closed_without_parsing() {
        // NewSessionTicket, KeyUpdate and an incomplete/unknown handshake.
        for payload in [&[4, 0, 0, 0][..], &[24, 0, 0, 1, 0], &[255]] {
            for flags in [0, libc::MSG_EOR] {
                let mut reader = RecordReader::default();
                let first = reader.consume(Some(HANDSHAKE), flags, payload).unwrap_err();
                assert_eq!(first.kind(), io::ErrorKind::Unsupported);
                assert_sticky_error(&mut reader, &first);
            }
        }
    }

    #[test]
    fn unknown_record_types_are_terminal() {
        for kind in [0, 20, 24, 255] {
            let mut reader = RecordReader::default();
            let first = reader.consume(Some(kind), libc::MSG_EOR, &[1]).unwrap_err();
            assert_eq!(first.kind(), io::ErrorKind::InvalidData);
            assert_sticky_error(&mut reader, &first);
        }
    }

    #[test]
    fn socket_errors_keep_errno_and_remain_terminal() {
        let mut reader = RecordReader::default();
        let first = reader.fail(io::Error::from_raw_os_error(libc::EBADMSG));
        assert_eq!(first.raw_os_error(), Some(libc::EBADMSG));
        assert_sticky_error(&mut reader, &first);
    }

    #[test]
    fn close_notify_send_must_accept_both_bytes_at_once() {
        assert!(check_close_notify_write(2).is_ok());
        assert_eq!(
            check_close_notify_write(0).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
        for sent in [1, 3] {
            assert_eq!(
                check_close_notify_write(sent).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}
