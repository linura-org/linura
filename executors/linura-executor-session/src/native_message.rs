//! Authenticate the sender of each fragment on a forwarded Unix stream.
//! SO_PEERCRED identifies the socket-pair creator, not a later descriptor holder.
use std::io::{self, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::unix::net::UnixStream;

use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, UCred};

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "native message identity unavailable",
    )
}

pub(super) fn read_chunk(stream: &UnixStream, bytes: &mut [u8]) -> io::Result<(usize, UCred)> {
    if bytes.is_empty() || bytes.len() > 16 || !rustix::net::sockopt::socket_passcred(stream)? {
        return Err(invalid());
    }
    // Exactly one credential fits. Even alignment padding cannot fit a second
    // cmsg header. Extra/unknown ancillary messages therefore truncate and fail
    // closed rather than being silently skipped by the ancillary iterator.
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmCredentials(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = rustix::net::recvmsg(
        stream,
        &mut [IoSliceMut::new(bytes)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    let mut credentials = None;
    let mut unexpected = false;
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmCredentials(sender) if credentials.is_none() => {
                credentials = Some(sender);
            }
            // Dropping the iterator closes any received descriptor, including
            // on truncated/error paths; no untrusted descriptor escapes.
            _ => unexpected = true,
        }
    }
    if received.bytes == 0
        || received.bytes > bytes.len()
        || received
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || unexpected
    {
        return Err(invalid());
    }
    Ok((received.bytes, credentials.ok_or_else(invalid)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    use std::io::{IoSlice, Read, Write};
    use std::os::fd::AsFd;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn enabled_pair() -> (UnixStream, UnixStream) {
        let (reader, writer) = value(UnixStream::pair());
        value(rustix::net::sockopt::set_socket_passcred(&reader, true));
        value(reader.set_read_timeout(Some(Duration::from_secs(2))));
        (reader, writer)
    }
    fn send_descriptor(socket: &UnixStream, descriptor: &UnixStream) {
        let fds = [descriptor.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&fds)));
        assert_eq!(
            value(rustix::net::sendmsg(
                socket,
                &[IoSlice::new(b"x")],
                &mut ancillary,
                SendFlags::NOSIGNAL
            )),
            1
        );
    }

    #[test]
    fn missing_passcred_invalid_bounds_and_eof_refuse() {
        let (reader, mut writer) = value(UnixStream::pair());
        value(writer.write_all(b"x"));
        assert!(read_chunk(&reader, &mut [0; 16]).is_err());
        value(rustix::net::sockopt::set_socket_passcred(&reader, true));
        assert!(read_chunk(&reader, &mut []).is_err());
        assert!(read_chunk(&reader, &mut [0; 17]).is_err());
        // Consume the old byte with the ordinary API; it is never admitted as
        // a message credential by the production path.
        value((&reader).read_exact(&mut [0]));
        drop(writer);
        assert!(read_chunk(&reader, &mut [0; 16]).is_err());
    }

    #[test]
    fn unexpected_descriptors_are_rejected_and_closed() {
        let (reader, writer) = enabled_pair();
        let (descriptor, mut observer) = value(UnixStream::pair());
        value(observer.set_read_timeout(Some(Duration::from_secs(2))));
        send_descriptor(&writer, &descriptor);
        drop(descriptor);
        assert!(read_chunk(&reader, &mut [0; 16]).is_err());
        // An accidentally retained SCM_RIGHTS descriptor would keep this peer
        // open. EOF proves closure without a racy global descriptor count.
        assert_eq!(value(observer.read(&mut [0])), 0);
    }

    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ignored = self.0.kill();
            let _ignored = self.0.wait();
        }
    }

    #[test]
    fn forwarded_pair_reports_actual_same_uid_sender_not_pair_creator() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            "linura-native-message-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let address = value(SocketAddr::from_abstract_name(name.as_bytes()));
        let listener = value(UnixListener::bind_addr(&address));
        value(listener.set_nonblocking(true));
        let (mut root, native) = enabled_pair();
        let creator = value(rustix::net::sockopt::socket_peercred(&root));
        assert_eq!(creator.pid, rustix::process::getpid());
        // Fixed unprivileged stdlib-only fixture, not a production command or
        // caller-selected program. Forward the endpoint exactly as adapters do.
        let script = r#"
import array, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3)
s.connect('\0' + sys.argv[1])
data, control, flags, address = s.recvmsg(1, socket.CMSG_SPACE(array.array('i').itemsize))
assert data == b'x' and flags == 0 and len(control) == 1
level, kind, raw = control[0]
assert level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS
fds = array.array('i'); fds.frombytes(raw)
assert len(fds) == 1
native = socket.socket(fileno=fds[0]); native.settimeout(3)
request = b'LNRV:1\n\0' + (1).to_bytes(8, 'big')
native.sendall(request)
reply = b''
while len(reply) < len(request):
    part = native.recv(len(request) - len(reply))
    assert part
    reply += part
assert reply == request
"#;
        let mut child = Child(value(
            std::process::Command::new("/usr/bin/python3")
                .args(["-I", "-S", "-c", script, &name])
                .spawn(),
        ));
        let deadline = Instant::now() + Duration::from_secs(3);
        let transfer = loop {
            match listener.accept() {
                Ok((connection, _)) => break connection,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => unreachable!("{error:?}"),
            }
        };
        // SO_PEERCRED is appropriate on this actual child-created connection;
        // authenticate it before disclosing the forwarded native endpoint.
        let connected = value(rustix::net::sockopt::socket_peercred(&transfer));
        assert_eq!(connected.pid.as_raw_nonzero().get() as u32, child.0.id());
        assert_eq!(connected.uid, rustix::process::getuid());
        send_descriptor(&transfer, &native);
        drop(native);
        let mut request = [0; 16];
        let mut read = 0;
        while read < request.len() {
            let (size, sender) = value(read_chunk(&root, &mut request[read..]));
            assert_eq!(sender, connected);
            assert_ne!(sender.pid, creator.pid);
            read += size;
        }
        assert_eq!(&request[..8], b"LNRV:1\n\0");
        assert_eq!(request[8..], 1_u64.to_be_bytes());
        value(root.write_all(&request));
        loop {
            if let Some(status) = value(child.0.try_wait()) {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
