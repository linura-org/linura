//! Read-only kernel lifetime witness. Subscribe before sampling the native
//! baseline; keep the SAME socket and kernfs descriptors through compositor
//! loss. Any uncertainty irreversibly invalidates the witness. No DRM master,
//! scanout operation, restoration command or authority is exposed here.
use std::collections::{BTreeMap, BTreeSet};
use std::io::IoSliceMut;
use std::os::fd::OwnedFd;

use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags};
use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{self, RecvAncillaryBuffer, RecvFlags, ReturnFlags};

const MAX_EVENTS: usize = 1024;
const MAX_EVENT_BYTES: usize = 8192;
const SYSFS_MAGIC: u64 = 0x6265_6572;
const READ: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);

fn unavailable() -> String {
    "independent display kernel continuity unavailable; no recovery permission".into()
}
fn number(raw: &str) -> Result<u64, String> {
    let value: u64 = raw.parse().map_err(|_| unavailable())?;
    if value.to_string() != raw || value == u64::MAX {
        return Err(unavailable());
    }
    Ok(value)
}
fn text(fd: &OwnedFd) -> Result<String, String> {
    // pread at zero is essential: reading an old seq_file offset could return
    // EOF or buffered history instead of re-entering the retained kernfs node.
    let mut bytes = [0; 128];
    let len = rustix::io::pread(fd, &mut bytes, 0).map_err(|_| unavailable())?;
    if len == 0 || len == bytes.len() {
        return Err(unavailable());
    }
    let raw = std::str::from_utf8(&bytes[..len]).map_err(|_| unavailable())?;
    Ok(raw.strip_suffix('\n').ok_or_else(unavailable)?.to_owned())
}
fn attribute(directory: &OwnedFd, name: &str) -> Result<OwnedFd, String> {
    let fd = fs::openat(directory, name, READ, Mode::empty()).map_err(|_| unavailable())?;
    let stat = fs::fstat(&fd).map_err(|_| unavailable())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != 0
        || stat.st_mode & 0o022 != 0
        || fs::fstatfs(&fd).map_err(|_| unavailable())?.f_type as u64 != SYSFS_MAGIC
    {
        return Err(unavailable());
    }
    Ok(fd)
}
fn sys_directory(sys: &OwnedFd, relative: &str) -> Result<OwnedFd, String> {
    // The kernel class symlink is expected. Resolve it ONLY beneath the held
    // real sysfs mount; never follow a magic link or an escaping filesystem.
    let fd = fs::openat2(
        sys,
        relative,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| unavailable())?;
    let stat = fs::fstat(&fd).map_err(|_| unavailable())?;
    if stat.st_uid != 0 || stat.st_mode & 0o022 != 0 {
        return Err(unavailable());
    }
    Ok(fd)
}

#[derive(Debug)]
struct Stream {
    initial: u64,
    last: u64,
    valid: bool,
    ancestors: BTreeSet<String>,
}
impl Stream {
    fn accept(&mut self, bytes: &[u8], kernel: bool) -> Result<(), String> {
        let result = self.parse(bytes, kernel);
        if result.is_err() {
            self.valid = false;
        }
        result
    }
    fn parse(&mut self, bytes: &[u8], kernel: bool) -> Result<(), String> {
        if !self.valid || !kernel || bytes.is_empty() || bytes.len() > MAX_EVENT_BYTES {
            return Err(unavailable());
        }
        let raw = std::str::from_utf8(bytes).map_err(|_| unavailable())?;
        let mut parts = raw.strip_suffix('\0').ok_or_else(unavailable)?.split('\0');
        let header = parts.next().ok_or_else(unavailable)?;
        let mut fields = BTreeMap::new();
        for (index, field) in parts.enumerate() {
            let (key, value) = field.split_once('=').ok_or_else(unavailable)?;
            if index >= 128
                || key.is_empty()
                || key.len() > 64
                || !key
                    .bytes()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
                || value.len() > 4096
                || fields.insert(key, value).is_some()
            {
                return Err(unavailable());
            }
        }
        let action = *fields.get("ACTION").ok_or_else(unavailable)?;
        let path = *fields.get("DEVPATH").ok_or_else(unavailable)?;
        let subsystem = *fields.get("SUBSYSTEM").ok_or_else(unavailable)?;
        let seq = number(fields.get("SEQNUM").ok_or_else(unavailable)?)?;
        if !matches!(
            action,
            "add" | "remove" | "change" | "move" | "online" | "offline" | "bind" | "unbind"
        ) || !path.starts_with('/')
            || path.len() < 2
            || path.contains("//")
            || path.bytes().any(|c| c.is_ascii_control())
            || path.split('/').any(|part| matches!(part, "." | ".."))
            || subsystem.is_empty()
            || header != format!("{action}@{path}")
            || seq == 0
            || fields.keys().any(|key| key.starts_with("SYNTH_"))
        {
            return Err(unavailable());
        }
        // Events queued before the initial seqnum read preceded the native
        // baseline. Once any later event is consumed, no rewind is permitted.
        if seq <= self.initial && self.last == self.initial {
            return Ok(());
        }
        if self.last.checked_add(1) != Some(seq)
            || subsystem == "drm"
            || self.ancestors.contains(path)
        {
            return Err(unavailable());
        }
        self.last = seq;
        Ok(())
    }
}

/// A subscription started BEFORE native sampling. It cannot be reconstructed
/// from a checkpoint or a replacement compositor's advertised identities.
#[derive(Debug)]
pub struct NativeDisplayKernelSubscription {
    sys: OwnedFd,
    sequence: OwnedFd,
    socket: OwnedFd,
    stream: Stream,
    power: PowerEpoch,
}
#[derive(Debug)]
struct PowerEpoch {
    success: OwnedFd,
    fail: OwnedFd,
    expected: [u64; 2],
}
impl PowerEpoch {
    fn capture(sys: &OwnedFd) -> Result<Self, String> {
        let directory = sys_directory(sys, "power/suspend_stats")?;
        let success = attribute(&directory, "success")?;
        let fail = attribute(&directory, "fail")?;
        let expected = [number(&text(&success)?)?, number(&text(&fail)?)?];
        let epoch = Self {
            success,
            fail,
            expected,
        };
        epoch.verify()?;
        Ok(epoch)
    }
    fn verify(&self) -> Result<(), String> {
        if [number(&text(&self.success)?)?, number(&text(&self.fail)?)?] != self.expected {
            return Err(unavailable());
        }
        Ok(())
    }
}
impl NativeDisplayKernelSubscription {
    pub fn begin() -> Result<Self, String> {
        if !rustix::process::geteuid().is_root() {
            return Err(unavailable());
        }
        let sys =
            fs::open("/sys", READ | OFlags::DIRECTORY, Mode::empty()).map_err(|_| unavailable())?;
        if fs::fstatfs(&sys).map_err(|_| unavailable())?.f_type as u64 != SYSFS_MAGIC {
            return Err(unavailable());
        }
        let kernel = sys_directory(&sys, "kernel")?;
        let sequence = attribute(&kernel, "uevent_seqnum")?;
        let socket = net::socket_with(
            net::AddressFamily::NETLINK,
            net::SocketType::DGRAM,
            net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
            Some(net::netlink::KOBJECT_UEVENT),
        )
        .map_err(|_| unavailable())?;
        net::sockopt::set_socket_recv_buffer_size(&socket, 256 * 1024)
            .map_err(|_| unavailable())?;
        net::bind(&socket, &SocketAddrNetlink::new(0, 1)).map_err(|_| unavailable())?;
        let initial = number(&text(&sequence)?)?;
        let power = PowerEpoch::capture(&sys)?;
        Ok(Self {
            sys,
            sequence,
            socket,
            stream: Stream {
                initial,
                last: initial,
                valid: true,
                ancestors: BTreeSet::new(),
            },
            power,
        })
    }

    fn drain(&mut self) -> Result<(), String> {
        for _ in 0..MAX_EVENTS {
            let mut bytes = [0; MAX_EVENT_BYTES];
            // Do not enable SO_PASSCRED: rustix 1.1 represents SCM_CREDENTIALS
            // pid as NonZero, whereas genuine kernel uevents have pid zero.
            // Authenticate the kernel multicast endpoint and global sequence
            // instead. Userspace injection through that endpoint itself needs
            // CAP_SYS_ADMIN in the owning network namespace; it grants no new
            // authority here and cannot revive a poisoned witness.
            let mut ancillary = RecvAncillaryBuffer::default();
            let msg = match net::recvmsg(
                &self.socket,
                &mut [IoSliceMut::new(&mut bytes)],
                &mut ancillary,
                RecvFlags::DONTWAIT,
            ) {
                Ok(msg) => msg,
                Err(rustix::io::Errno::AGAIN) => return Ok(()),
                Err(_) => return Err(unavailable()), // Includes ENOBUFS.
            };
            let kernel = msg
                .address
                .and_then(|addr| SocketAddrNetlink::try_from(addr).ok())
                .is_some_and(|addr| addr.pid() == 0 && addr.groups() == 1)
                && !msg
                    .flags
                    .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC);
            self.stream.accept(&bytes[..msg.bytes], kernel)?;
        }
        Err(unavailable()) // A busy or unreadable stream cannot widen budgets.
    }

    pub fn bind(mut self, outputs: &[[u32; 3]]) -> Result<NativeDisplayKernelWitness, String> {
        if outputs.is_empty() || outputs.len() > 16 {
            return Err(unavailable());
        }
        let mut unique = BTreeSet::new();
        let mut connectors = Vec::new();
        for output in outputs {
            if output[0] != 226 || output[1] > 63 || output[2] == 0 || !unique.insert(*output) {
                return Err(unavailable());
            }
            let (connector, ancestors) = Connector::capture(&self.sys, *output)?;
            self.stream.ancestors.extend(ancestors);
            connectors.push(connector);
        }
        self.drain()?;
        let mut witness = NativeDisplayKernelWitness {
            subscription: self,
            connectors,
        };
        witness.verify()?;
        Ok(witness)
    }
}

#[derive(Debug)]
struct Connector {
    // Hold real kernfs attribute descriptors, not path names to reopen later.
    dev: OwnedFd,
    id: OwnedFd,
    status: OwnedFd,
    expected: [u32; 3],
}
impl Connector {
    fn capture(sys: &OwnedFd, expected: [u32; 3]) -> Result<(Self, BTreeSet<String>), String> {
        let card_name = format!("card{}", expected[1]);
        let card = sys_directory(sys, &format!("class/drm/{card_name}"))?;
        let link = fs::readlinkat(sys, format!("class/drm/{card_name}"), Vec::new())
            .map_err(|_| unavailable())?;
        let path =
            std::path::Path::new("class/drm").join(link.to_str().map_err(|_| unavailable())?);
        let (relative, ancestors) = card_path(&path)?;
        let direct = sys_directory(sys, &relative)?;
        let original = fs::fstat(&card).map_err(|_| unavailable())?;
        let resolved = fs::fstat(&direct).map_err(|_| unavailable())?;
        if (original.st_dev, original.st_ino) != (resolved.st_dev, resolved.st_ino) {
            return Err(unavailable());
        }
        let mut found = None;
        let mut count = 0;
        for entry in fs::Dir::read_from(&card).map_err(|_| unavailable())? {
            let entry = entry.map_err(|_| unavailable())?;
            count += 1;
            if count > 256 {
                return Err(unavailable());
            }
            let name = entry.file_name().to_str().map_err(|_| unavailable())?;
            if !name.starts_with(&format!("{card_name}-")) {
                continue;
            }
            if name.len() > 128
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            {
                return Err(unavailable());
            }
            let directory = fs::openat(&card, name, READ | OFlags::DIRECTORY, Mode::empty())
                .map_err(|_| unavailable())?;
            let id = attribute(&directory, "connector_id")?;
            if number(&text(&id)?)? != u64::from(expected[2]) {
                continue;
            }
            if found.is_some() {
                return Err(unavailable());
            }
            found = Some(Self {
                dev: attribute(&card, "dev")?,
                id,
                status: attribute(&directory, "status")?,
                expected,
            });
        }
        let connector = found.ok_or_else(unavailable)?;
        connector.verify()?;
        Ok((connector, ancestors))
    }
    fn verify(&self) -> Result<(), String> {
        if text(&self.dev)? != format!("{}:{}", self.expected[0], self.expected[1])
            || number(&text(&self.id)?)? != u64::from(self.expected[2])
            || text(&self.status)? != "connected"
        {
            return Err(unavailable());
        }
        Ok(())
    }
}

fn card_path(path: &std::path::Path) -> Result<(String, BTreeSet<String>), String> {
    use std::path::Component;
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => {
                let name = name.to_str().ok_or_else(unavailable)?;
                if name.len() > 255 || name.bytes().any(|b| b.is_ascii_control()) {
                    return Err(unavailable());
                }
                names.push(name);
            }
            Component::ParentDir if names.pop().is_some() => (),
            _ => return Err(unavailable()),
        }
    }
    if names.len() < 3 || names.len() > 64 || names[0] != "devices" {
        return Err(unavailable());
    }
    let relative = names.join("/");
    let mut ancestors = BTreeSet::new();
    for length in 2..=names.len() {
        ancestors.insert(format!("/{}", names[..length].join("/")));
    }
    Ok((relative, ancestors))
}

/// Live process-local evidence, deliberately not Clone or serializable. Service
/// restart loses continuity; durable historical records cannot recreate it.
#[derive(Debug)]
pub struct NativeDisplayKernelWitness {
    subscription: NativeDisplayKernelSubscription,
    connectors: Vec<Connector>,
}
impl NativeDisplayKernelWitness {
    /// Bounded synchronous revalidation; no polling worker or hidden retries.
    /// A failed check permanently poisons this original witness.
    pub fn verify(&mut self) -> Result<(), String> {
        let result = (|| {
            if !self.subscription.stream.valid {
                return Err(unavailable());
            }
            self.subscription.drain()?;
            self.subscription.power.verify()?;
            for connector in &self.connectors {
                connector.verify()?;
            }
            let seq = number(&text(&self.subscription.sequence)?)?;
            self.subscription.drain()?;
            self.subscription.power.verify()?;
            if self.subscription.stream.last < seq
                || number(&text(&self.subscription.sequence)?)? != self.subscription.stream.last
            {
                return Err(unavailable());
            }
            Ok(())
        })();
        if result.is_err() {
            self.subscription.stream.valid = false;
        }
        result
    }
}

#[cfg(test)]
mod tests;
