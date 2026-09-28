// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ugpibd contributors
//
// HiSLIP server. Accepts one TCP connection per session-channel. Each client
// opens two connections to the same port: a synchronous channel for
// data/trigger, and an asynchronous channel for lock/clear/status/REN. They
// are paired by the 16-bit session id the server hands out on the sync
// Initialize, which the client echoes on AsyncInitialize.
//
// Locks are real: AsyncLock/AsyncLockInfo are backed by lock.rs and enforced
// against Data/Trigger/device-clear traffic from sessions that do not hold
// them. TLS/SASL handshakes are rejected. Multi-device is out of scope: one
// bus, addressed per session by the hislip<N> sub-address.
//
// Service requests reach the client from two places. When the adapter reports
// SRQ while the bus is idle, a per-session task serial-polls the device and
// pushes an AsyncServiceRequest carrying the status byte. When one is raised by
// a command this session is running, `Device::execute` reports it — see
// hislip/instrument.rs for why it has to be noticed there. Those are the only
// messages the server sends unsolicited, so they are also the only ones a
// client must be prepared to see mid-round-trip.
//
// Both §3 modes are implemented, which is why the synchronous channel is read
// by its own task rather than inline: the interrupted error is defined in terms
// of a *server input queue*, so one has to exist here instead of in the socket
// buffer, and overlapped mode needs the same queue to let a client run ahead.
// Execution stays strictly serial in either mode — one GPIB bus — so what the
// mode actually selects is whether a client that runs ahead is told it made a
// mistake (§3.1) or quietly served in order (§3.2).

use std::collections::{HashMap, VecDeque};
use std::io;
use std::str::from_utf8;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use byteorder::{ByteOrder, NetworkEndian};
use tokio::io::{AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Mutex};
use tracing::{debug, info, warn};

use super::errors::{FatalErrorCode, NonFatalErrorCode};
use super::lock::{self, LockRegistry};
use super::messages::{
    send_fatal, send_nonfatal, AsyncInitializeResponseControl, AsyncInitializeResponseParameter,
    FeatureBitmap, InitializeParameter, InitializeResponseControl, InitializeResponseParameter,
    Message, MessageType, RmtDeliveredControl,
};
use super::protocol::{Protocol, SUPPORTED_PROTOCOL};
use super::DEFAULT_SUBADDRESS;

/// What running one command produced.
#[derive(Debug, Default)]
pub struct Execution {
    /// The instrument's reply, or `None` for a command we did not read back.
    pub data: Option<Vec<u8>>,
    /// Status byte of a service request the instrument raised while this
    /// command was running, if the device noticed one. Carried out here
    /// because the window it lives in is inside `execute` — see
    /// [`crate::hislip::instrument::GpibInstrument`].
    pub service_request: Option<u8>,
}

impl From<Option<Vec<u8>>> for Execution {
    fn from(data: Option<Vec<u8>>) -> Self {
        Self {
            data,
            service_request: None,
        }
    }
}

/// A HiSLIP device endpoint. The server resolves a subaddress to one of
/// these on Initialize and then drives all per-session I/O through it.
///
/// All methods are cancel-safe at the GPIB-bus level: the underlying
/// [`crate::backend::agilent_82357::gpib::GpibController`] serializes calls via its own mutex.
#[async_trait::async_trait]
pub trait Device: Send + Sync + 'static {
    /// Execute a full query: write `cmd` to the instrument with EOI on the
    /// last byte, then read a response. `expect_response` is a *hint* from the
    /// command text: when true the device commits to an addressed read; when
    /// false it may still read if the instrument reports pending output (MAV),
    /// so a mis-hinted query is recovered rather than stranded.
    async fn execute(&self, cmd: &[u8], expect_response: bool) -> Result<Execution>;

    /// Send a GPIB trigger (GET) to the instrument.
    async fn trigger(&self) -> Result<()>;

    /// Send Selected Device Clear to the instrument.
    async fn clear(&self) -> Result<()>;

    /// Drive REN on/off.
    async fn set_remote(&self, remote: bool) -> Result<()>;

    /// Assert REN and address this instrument, putting it into remote state.
    async fn go_to_remote(&self) -> Result<()> {
        anyhow::bail!("this device cannot be addressed into remote state")
    }

    /// Send an addressed Go To Local to this instrument.
    async fn go_to_local(&self) -> Result<()> {
        anyhow::bail!("this device cannot be sent Go To Local")
    }

    /// Send Local Lockout, which the standard defines only bus-wide.
    async fn local_lockout(&self) -> Result<()> {
        anyhow::bail!("this device cannot be sent Local Lockout")
    }

    /// Read the instrument's serial-poll status byte.
    ///
    /// No default: 0 is a meaningful status ("nothing to report"), so an
    /// implementation that has no way to poll must return an error rather than
    /// a value the caller cannot distinguish from a real reading.
    async fn get_status(&self) -> Result<u8>;

    /// Subscribe to service requests raised by this device, so the session can
    /// forward them to the client as `AsyncServiceRequest`. `None` means the
    /// underlying adapter has no way to report SRQ, and the session simply
    /// never pushes one.
    async fn subscribe_srq(&self) -> Option<tokio::sync::broadcast::Receiver<()>> {
        None
    }

    /// Whether any device on the bus is currently asserting SRQ — a level read,
    /// not an event.
    ///
    /// Errors when the adapter cannot tell. Callers must not read that as "no
    /// SRQ": a fabricated no is indistinguishable from a quiet bus.
    async fn srq_asserted(&self) -> Result<bool> {
        anyhow::bail!("this device cannot read the SRQ line")
    }

    /// Key identifying the physical resource behind this device, used to scope
    /// locks. Two sessions that reach the same instrument must return the same
    /// key, and two that reach different instruments must not: locking the DMM
    /// has no business locking out the counter on the same bus.
    fn resource_key(&self) -> String {
        "default".to_string()
    }
}

/// How long the sync loop waits, after handing a fatal error to the async
/// channel, before tearing the session down. Long enough for a loopback or LAN
/// write, short enough not to delay a close anyone is waiting on — and the
/// session is already over either way, so the cost of it being too short is a
/// missed copy rather than a stuck client.
const FATAL_MIRROR_GRACE: std::time::Duration = std::time::Duration::from_millis(50);

/// First MessageID a client uses, per §6.14. A status query arriving before the
/// client has sent anything quotes this minus two.
const FIRST_MESSAGE_ID: u32 = 0xffff_ff00;

/// §3: which of the two message-exchange disciplines a session is running.
///
/// The difference is not concurrency — a single GPIB bus executes one command
/// at a time either way — but what the server owes a client that sends a second
/// query before reading the first one's answer. Synchronized calls that the
/// interrupted error and throws the stale response away; overlapped buffers and
/// answers both, in order.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Mode {
    Synchronized,
    Overlapped,
}

impl Mode {
    fn from_overlapped(overlapped: bool) -> Self {
        if overlapped {
            Mode::Overlapped
        } else {
            Mode::Synchronized
        }
    }
}

/// How far the synchronous channel has got, for the async channel to defer
/// against (§6.5.1, §6.7). The epoch travels with the watermark so a waiter can
/// tell "the message you are waiting for was acted on" from "a device clear
/// threw it away", which are the two outcomes those sections distinguish.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct SyncProgress {
    epoch: u64,
    message_id: u32,
}

/// Why a wait for a named message ended.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Awaited {
    Processed,
    Cleared,
}

/// Has the message carrying `id` been acted on, given watermark `seen`?
///
/// MessageIDs are a 32-bit counter that wraps, so this is a serial-number
/// comparison rather than `>=`: an id half the space ahead reads as "not yet",
/// and one half the space behind as "long done".
fn message_reached(seen: u32, id: u32) -> bool {
    (seen.wrapping_sub(id) as i32) >= 0
}

/// IEEE-488 status byte bit 6: the device is requesting service. Set in the
/// byte returned by a serial poll of whichever device pulled SRQ.
pub const STB_RQS: u8 = 0x40;

/// IEEE-488 status byte bit 4: message available — the device has output
/// queued that nobody has read yet.
pub const STB_MAV: u8 = 0x10;

/// How long the SRQ forwarder waits for the async channel's write lock before
/// saying so. Comfortably longer than any legitimate hold — the async loop only
/// holds it to service one request — so this firing means something is wedged.
/// It only logs; the forwarder keeps waiting.
const WRITE_LOCK_STUCK_AFTER: std::time::Duration = std::time::Duration::from_secs(10);

/// How long to keep re-polling this session's device while the SRQ line stays
/// asserted. Bounded because the line can legitimately stay low indefinitely —
/// a device with no session bound to it can request service that nothing will
/// ever clear, and that must not become a busy loop.
const SRQ_RECHECK_BUDGET: std::time::Duration = std::time::Duration::from_millis(500);

/// Gap between those re-polls. Each one is a bus transaction, so this trades
/// how fast an overlapping request is noticed against bus traffic.
const SRQ_RECHECK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

#[derive(Debug, Clone)]
pub struct Config {
    pub vendor_id: u16,
    pub max_message_size: u64,
    pub max_sessions: usize,
    /// The mode this server announces at Initialize and proposes at device
    /// clear. Both are implemented, and a client that wants the other one says
    /// so in the device-clear feature negotiation (§6.12.1); this only decides
    /// which one a session starts in. Synchronized, because that is what a VISA
    /// client assumes when it does not ask.
    pub prefer_overlap: bool,
    /// The lock registry this server enforces. Passed in rather than created
    /// here because locks protect the *instrument*: a daemon serving several
    /// front-ends hands the same registry to each, so a lock taken over one
    /// protocol excludes I/O arriving over another. The default is a fresh
    /// registry, which is right for a daemon (or test) with one front-end.
    pub locks: Arc<LockRegistry>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            vendor_id: 0xBEEF,
            max_message_size: 1024 * 1024,
            max_sessions: 16,
            prefer_overlap: false,
            locks: Arc::new(LockRegistry::new()),
        }
    }
}

/// Server entry point. `device_for` resolves a subaddress string (e.g.
/// "hislip0", "gpib0,14") to a boxed [`Device`]. Returning `None` causes
/// the connection to be rejected with InvalidInitialization.
pub async fn run<F>(listener: TcpListener, config: Config, device_for: F) -> io::Result<()>
where
    F: Fn(&str) -> Option<Arc<dyn Device>> + Send + Sync + 'static,
{
    info!("HiSLIP listening on {}", listener.local_addr()?);
    let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
    let locks = config.locks.clone();
    let device_for = Arc::new(device_for);

    loop {
        let (stream, addr) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let registry = registry.clone();
        let locks = locks.clone();
        let config = config.clone();
        let device_for = device_for.clone();
        tokio::spawn(async move {
            info!(%addr, "hislip client connected");
            if let Err(e) = handle_connection(stream, config, registry, locks, device_for).await {
                warn!(%addr, "hislip client error: {e:#}");
            } else {
                info!(%addr, "hislip client disconnected");
            }
        });
    }
}

type Registry = Arc<Mutex<HashMap<u16, Arc<SessionEntry>>>>;

struct SessionEntry {
    /// This session's id — also how the lock registry identifies it.
    id: u16,
    protocol: Protocol,
    /// `max_message_size` the client says it can receive; chunked response
    /// writes on the sync channel respect this.
    client_max_message_size: Mutex<u64>,
    device: Arc<dyn Device>,
    /// Tracks whether an async channel has already bound to this session.
    async_bound: Mutex<bool>,
    /// Server-wide lock state, and the resource key this session locks under.
    locks: Arc<LockRegistry>,
    resource: String,
    /// The last status byte the daemon consumed on this client's behalf.
    ///
    /// A serial poll clears RQS at the instrument, so once the daemon has
    /// polled — which it must, to put a status byte in `AsyncServiceRequest` —
    /// the client's own `AsyncStatusQuery` would read a bit that has already
    /// been taken. Hold it and hand it over once. pyvisa-py hit the mirror
    /// image of this in VXI-11, where polling inside the SRQ handler broke
    /// because the bit was not cached.
    consumed_stb: std::sync::Mutex<Option<u8>>,
    /// Bumped by every device clear, so the sync loop drops a half-assembled
    /// message rather than finishing it with bytes from before the clear.
    clear_epoch: AtomicU64,
    /// MAV, per §6.14.1: this client has a response it has not consumed.
    ///
    /// Set when the first Data/DataEND of a reply goes out, cleared when the
    /// client indicates RMT-delivered. Deliberately independent of `*SRE`: the
    /// service request mask gates RQS, not MAV, so a client that polls the
    /// status byte without enabling service requests must still see that a
    /// reply is waiting.
    mav: AtomicBool,
    /// MessageID of the most recent Data/DataEND/Trigger from this client.
    /// §6.14.3 reports MAV false to a status query quoting any other id.
    last_message_id: AtomicU32,
    /// Whether this session is in overlapped mode (§3.2) rather than
    /// synchronized (§3.1). Not fixed for the life of the session: §6.12.1
    /// renegotiates it on every device clear.
    overlapped: AtomicBool,
    /// The id the *server* stamps on its next outgoing Data/DataEND in
    /// overlapped mode (§3.2.1). Unused in synchronized mode, where a reply
    /// quotes the client message that produced it instead.
    server_message_id: AtomicU32,
    /// §3.1.1 rule 2: the server has sent an RMT the client has not yet said it
    /// delivered to its application layer. Compared against the RMT-delivered
    /// flag on the next message to detect an interrupted exchange.
    rmt_expected: AtomicBool,
    /// How far the sync channel has got through this client's messages, which
    /// is what §6.5.1 and §6.7 make their deferrals wait on.
    progress: watch::Sender<SyncProgress>,
    /// Service requests the server raises itself, from the sync loop to
    /// whichever task owns the async channel's writer.
    async_tx: mpsc::Sender<AsyncPush>,
    async_rx: Mutex<Option<mpsc::Receiver<AsyncPush>>>,
    /// The other direction of §6.2: a fatal the async channel detected, to be
    /// written on the synchronous one.
    sync_tx: mpsc::Sender<(FatalErrorCode, String)>,
    sync_rx: Mutex<Option<mpsc::Receiver<(FatalErrorCode, String)>>>,
}

/// Something the session needs written on the async channel, from a task that
/// does not own that channel's writer.
#[derive(Debug)]
enum AsyncPush {
    /// A service request the daemon observed on this session's behalf.
    ServiceRequest(u8),
    /// §6.11: the async half of the interrupted transaction, queued by the sync
    /// loop because the other half goes out on the channel it owns.
    Interrupted(u32),
    /// §6.2: a desync is reported on *both* channels before closing, so the
    /// sync loop hands its fatal to whoever owns the async writer.
    Fatal(FatalErrorCode, String),
}

/// Depth of the self-raised service request queue. A service request is a
/// level, not a count — a client that has not drained one does not need the
/// next four — so a small queue that drops on overflow loses nothing.
const SRQ_QUEUE_DEPTH: usize = 4;

impl SessionEntry {
    fn new(
        id: u16,
        protocol: Protocol,
        device: Arc<dyn Device>,
        locks: Arc<LockRegistry>,
        max_message_size: u64,
        overlapped: bool,
    ) -> Self {
        let (async_tx, async_rx) = mpsc::channel(SRQ_QUEUE_DEPTH);
        // One fatal ends the session, so there is never a second to queue.
        let (sync_tx, sync_rx) = mpsc::channel(1);
        Self {
            id,
            protocol,
            client_max_message_size: Mutex::new(max_message_size),
            resource: device.resource_key(),
            device,
            async_bound: Mutex::new(false),
            locks,
            consumed_stb: std::sync::Mutex::new(None),
            clear_epoch: AtomicU64::new(0),
            mav: AtomicBool::new(false),
            // The id a client quotes before it has sent anything, per §6.14.
            last_message_id: AtomicU32::new(FIRST_MESSAGE_ID.wrapping_sub(2)),
            overlapped: AtomicBool::new(overlapped),
            server_message_id: AtomicU32::new(FIRST_MESSAGE_ID),
            rmt_expected: AtomicBool::new(false),
            progress: watch::Sender::new(SyncProgress {
                epoch: 0,
                message_id: FIRST_MESSAGE_ID.wrapping_sub(2),
            }),
            async_tx,
            async_rx: Mutex::new(Some(async_rx)),
            sync_tx,
            sync_rx: Mutex::new(Some(sync_rx)),
        }
    }

    /// May this session do I/O right now, or is somebody else holding a lock?
    fn has_access(&self) -> bool {
        self.locks
            .has_access(&self.resource, lock::hislip_id(self.id))
    }

    /// Park until this session may touch the bus. See
    /// [`LockRegistry::wait_for_access`] for why this waits instead of
    /// refusing.
    async fn wait_for_access(&self) {
        if !self.has_access() {
            debug!(
                session = self.id,
                resource = %self.resource,
                "another client holds the lock; leaving this message unprocessed"
            );
            self.locks
                .wait_for_access(&self.resource, lock::hislip_id(self.id))
                .await;
        }
    }

    /// Note a Data/DataEND/Trigger arriving from the client.
    ///
    /// Two pieces of §6.14 bookkeeping: the id a later status query has to
    /// quote, and the RMT-delivered flag, which is how the client says it has
    /// consumed the previous response.
    fn note_client_message(&self, msg: &Message) {
        self.last_message_id
            .store(msg.message_parameter, Ordering::Release);
        let delivered = RmtDeliveredControl(msg.control_code).rmt_delivered();
        if delivered {
            self.mav.store(false, Ordering::Release);
        }
        if self.mode() == Mode::Synchronized {
            // §3.1.1 rule 2. Agreement clears RMT-expected; disagreement is an
            // interrupted error the spec deliberately keeps server-side, so it
            // is logged and nothing goes out on the wire.
            let expected = self.rmt_expected.load(Ordering::Acquire);
            if expected == delivered {
                self.rmt_expected.store(false, Ordering::Release);
            } else {
                warn!(
                    session = self.id,
                    expected, delivered, "interrupted: RMT-delivered disagrees with RMT-expected"
                );
            }
        }
        // A fresh command makes any status byte we are holding stale — `*CLS`
        // most obviously, but any command that changes the status registers.
        // Cheaper and more honest than parsing the payload to find out which.
        self.take_consumed_stb();
    }

    fn mode(&self) -> Mode {
        Mode::from_overlapped(self.overlapped.load(Ordering::Acquire))
    }

    fn set_mode(&self, mode: Mode) {
        self.overlapped
            .store(mode == Mode::Overlapped, Ordering::Release);
    }

    /// The id for the next server-originated Data/DataEND in overlapped mode,
    /// advancing the counter by two per §3.2.1.
    fn next_server_message_id(&self) -> u32 {
        self.server_message_id.fetch_add(2, Ordering::AcqRel)
    }

    /// The client says it has taken delivery of the outstanding response.
    /// Carried by Data/DataEND/Trigger and by AsyncStatusQuery alike (§6.14.1).
    fn note_rmt_delivered(&self) {
        self.mav.store(false, Ordering::Release);
        self.rmt_expected.store(false, Ordering::Release);
    }

    /// An RMT has just gone out, so the client owes us an acknowledgement of it
    /// on its next flag-carrying message (§3.1.1 rule 2).
    fn note_rmt_sent(&self) {
        self.rmt_expected.store(true, Ordering::Release);
    }

    /// The sync channel has finished acting on the message carrying
    /// `message_id`, releasing anything deferred behind it.
    ///
    /// `epoch` is the caller's snapshot of the clear counter: a device clear
    /// that overtook this message already rewound the watermark, and pushing a
    /// stale one back over it would leave waiters parked for an id that is
    /// never coming again.
    fn note_message_processed(&self, epoch: u64, message_id: u32) {
        self.progress.send_if_modified(|p| {
            if p.epoch != epoch {
                return false;
            }
            p.message_id = message_id;
            true
        });
    }

    /// Whether the message carrying `id` has already been acted on.
    fn message_processed(&self, id: u32) -> bool {
        message_reached(self.progress.borrow().message_id, id)
    }

    /// Park until the sync channel has acted on the message carrying `id`, or
    /// a device clear makes it moot.
    async fn wait_for_message(&self, id: u32) -> Awaited {
        let mut rx = self.progress.subscribe();
        let epoch = {
            let p = *rx.borrow_and_update();
            if message_reached(p.message_id, id) {
                return Awaited::Processed;
            }
            p.epoch
        };
        loop {
            if rx.changed().await.is_err() {
                return Awaited::Cleared;
            }
            let p = *rx.borrow_and_update();
            if p.epoch != epoch {
                return Awaited::Cleared;
            }
            if message_reached(p.message_id, id) {
                return Awaited::Processed;
            }
        }
    }

    /// Put the session back to its power-on state, and void whatever the sync
    /// loop is part-way through.
    ///
    /// Both MessageID counters reset here, per §3.1.2 and §3.2.1, so that the
    /// 0xfffffefe a client quotes straight after a clear lines up again.
    fn reset_for_device_clear(&self) {
        self.mav.store(false, Ordering::Release);
        self.rmt_expected.store(false, Ordering::Release);
        self.last_message_id
            .store(FIRST_MESSAGE_ID.wrapping_sub(2), Ordering::Release);
        self.server_message_id
            .store(FIRST_MESSAGE_ID, Ordering::Release);
        self.take_consumed_stb();
        // Last: the sync loop watches this to decide that everything before it
        // is void, so the state above has to already be reset when it looks.
        let epoch = self.clear_epoch.fetch_add(1, Ordering::Release) + 1;
        // Rewinding the watermark under the new epoch is also what releases
        // anything §6.5.1 or §6.7 has parked on a message that no longer exists.
        // `send_replace` rather than `send`: the latter reports "no receivers"
        // by leaving the value alone, and a session with nothing deferred right
        // now would keep a watermark from before the clear.
        self.progress.send_replace(SyncProgress {
            epoch,
            message_id: FIRST_MESSAGE_ID.wrapping_sub(2),
        });
    }

    /// MAV as a status-byte bit, for a status query quoting `message_id`.
    fn mav_bit(&self, message_id: u32) -> u8 {
        if self.mode() == Mode::Overlapped {
            // §6.14.2: MAV is true while anything the server has sent has not
            // reached the client's application layer. The client names the last
            // one that did, so anything other than the id we most recently used
            // means something is still in flight.
            let next = self.server_message_id.load(Ordering::Acquire);
            return if message_id == next.wrapping_sub(2) {
                0
            } else {
                STB_MAV
            };
        }
        if !self.mav.load(Ordering::Acquire) {
            return 0;
        }
        let expected = self.last_message_id.load(Ordering::Acquire);
        if message_id != expected {
            // §6.14.3: a status query that does not quote the most recent
            // Data/DataEND/Trigger is answered with MAV false.
            debug!(
                message_id,
                expected, "status query quotes a stale message id; reporting MAV false"
            );
            return 0;
        }
        STB_MAV
    }

    /// Push a service request the daemon observed on this session's behalf,
    /// remembering the status byte for the client's next `AsyncStatusQuery`.
    /// Dropped if no async channel is bound or the client is not keeping up —
    /// see [`SRQ_QUEUE_DEPTH`].
    fn raise_service_request(&self, stb: u8) {
        *self.consumed_stb.lock().unwrap() = Some(stb);
        if self
            .async_tx
            .try_send(AsyncPush::ServiceRequest(stb))
            .is_err()
        {
            debug!(stb, "no async channel to raise a service request on");
        }
    }

    /// Mirror a fatal error onto the async channel, per §6.2.
    fn mirror_fatal(&self, code: FatalErrorCode, message: &str) {
        let push = AsyncPush::Fatal(code, message.to_string());
        if self.async_tx.try_send(push).is_err() {
            debug!("no async channel to mirror the fatal error onto");
        }
    }

    /// Queue the `AsyncInterrupted` half of §6.11. The sync half is written by
    /// the caller, which owns that channel's writer.
    fn raise_interrupted(&self, message_id: u32) {
        if self
            .async_tx
            .try_send(AsyncPush::Interrupted(message_id))
            .is_err()
        {
            debug!(message_id, "no async channel to report interrupted on");
        }
    }

    /// The same, in the other direction: a fatal the async channel detected,
    /// written on the synchronous one.
    fn mirror_fatal_to_sync(&self, code: FatalErrorCode, message: &str) {
        if self.sync_tx.try_send((code, message.to_string())).is_err() {
            debug!("could not mirror the fatal error onto the sync channel");
        }
    }

    /// Take the status byte the daemon consumed, if it has not been handed
    /// over yet.
    fn take_consumed_stb(&self) -> Option<u8> {
        self.consumed_stb.lock().unwrap().take()
    }
}

async fn handle_connection<F>(
    stream: TcpStream,
    config: Config,
    registry: Registry,
    locks: Arc<LockRegistry>,
    device_for: Arc<F>,
) -> io::Result<()>
where
    F: Fn(&str) -> Option<Arc<dyn Device>> + Send + Sync + 'static,
{
    let (rd, wr) = stream.into_split();
    let mut rd = BufReader::new(rd);
    let mut wr = BufWriter::new(wr);

    // A fresh connection must begin with either Initialize (sync channel) or
    // AsyncInitialize (async channel). We read one message and dispatch.
    let first = match Message::read_from(&mut rd, config.max_message_size).await? {
        Ok(m) => m,
        Err(e) => {
            Message::from(e).write_to(&mut wr).await?;
            wr.flush().await?;
            return Ok(());
        }
    };

    match first.message_type {
        MessageType::Initialize => {
            init_sync(first, rd, wr, config, registry, locks, device_for).await
        }
        MessageType::AsyncInitialize => init_async(first, rd, wr, config, registry).await,
        other => {
            send_fatal(
                &mut wr,
                FatalErrorCode::InvalidInitialization,
                format!("first message must be (Async)Initialize, got {other:?}"),
            )
            .await?;
            Ok(())
        }
    }
}

async fn init_sync<R, W, F>(
    init: Message,
    rd: R,
    mut wr: W,
    config: Config,
    registry: Registry,
    locks: Arc<LockRegistry>,
    device_for: Arc<F>,
) -> io::Result<()>
where
    // Send + 'static because the sync loop hands the reader to its own task;
    // see [`sync_reader`] for why the read has to run ahead of execution.
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    // Send + 'static so the writer can be shared with the task that mirrors a
    // fatal error here from the async channel, as init_async already requires.
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    F: Fn(&str) -> Option<Arc<dyn Device>> + Send + Sync + 'static,
{
    let params = InitializeParameter(init.message_parameter);
    let client_protocol = params.client_protocol();
    let protocol = std::cmp::min(SUPPORTED_PROTOCOL, client_protocol);

    let subaddr = match String::from_utf8(init.payload) {
        Ok(s) if s.is_empty() => DEFAULT_SUBADDRESS.to_string(),
        Ok(s) => s,
        Err(_) => {
            send_fatal(
                &mut wr,
                FatalErrorCode::InvalidInitialization,
                "subaddress is not valid UTF-8",
            )
            .await?;
            return Ok(());
        }
    };

    let device = match device_for(&subaddr) {
        Some(d) => d,
        None => {
            send_fatal(
                &mut wr,
                FatalErrorCode::InvalidInitialization,
                format!("unknown subaddress: {subaddr}"),
            )
            .await?;
            return Ok(());
        }
    };

    // Allocate a session id and register. Session ids are 16-bit, we use
    // even numbers and wrap; collisions would only happen with > 32k
    // concurrent clients.
    let (session_id, entry) = {
        let mut reg = registry.lock().await;
        if reg.len() >= config.max_sessions {
            drop(reg);
            send_fatal(
                &mut wr,
                FatalErrorCode::MaximumClientsExceeded,
                "too many active sessions",
            )
            .await?;
            return Ok(());
        }
        let mut id: u16 = 0;
        while reg.contains_key(&id) {
            id = id.wrapping_add(2);
            if id == 0 {
                drop(reg);
                send_fatal(
                    &mut wr,
                    FatalErrorCode::MaximumClientsExceeded,
                    "out of session ids",
                )
                .await?;
                return Ok(());
            }
        }
        // Built under the registry lock, so the id it carries cannot be handed
        // to a second session in between.
        let entry = Arc::new(SessionEntry::new(
            id,
            protocol,
            device.clone(),
            locks.clone(),
            config.max_message_size,
            config.prefer_overlap,
        ));
        reg.insert(id, entry.clone());
        (id, entry)
    };

    debug!(session_id, %subaddr, %protocol, "hislip sync initialized");

    let resp_param = InitializeResponseParameter::new(protocol, session_id);
    // §6.1: this bit states the mode the session *starts* in, not a capability
    // — both are implemented, and §6.12.1 lets the client switch at any device
    // clear.
    let resp_ctrl = InitializeResponseControl::new(config.prefer_overlap, false, false);
    MessageType::InitializeResponse
        .message_params(resp_ctrl.0, resp_param.0)
        .no_payload()
        .write_to(&mut wr)
        .await?;
    wr.flush().await?;

    let guard = RegistrationGuard {
        id: session_id,
        registry: registry.clone(),
        locks,
    };
    // Shared so the async channel can have a fatal error written here too
    // (§6.2). The task owning the receiving end dies with this function.
    let writer = Arc::new(Mutex::new(wr));
    let _fatal_task = entry
        .sync_rx
        .lock()
        .await
        .take()
        .map(|rx| TaskGuard(tokio::spawn(sync_fatal_pusher(rx, writer.clone()))));
    let result = sync_loop(rd, &writer, entry.clone(), config).await;
    drop(guard);
    result
}

/// Write a fatal error the *async* channel detected onto the synchronous one.
///
/// §6.2 wants a desync reported on both channels and the connection closed, so
/// this shuts the writer down afterwards: the sync loop is parked in a read
/// that will not return until the client says something, and after a fatal it
/// never will.
async fn sync_fatal_pusher<W>(
    mut rx: mpsc::Receiver<(FatalErrorCode, String)>,
    writer: Arc<Mutex<W>>,
) where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Some((code, message)) = rx.recv().await else {
        return;
    };
    let mut wr = writer.lock().await;
    debug!("mirroring a fatal error onto the synchronous channel");
    if let Err(e) = send_fatal(&mut *wr, code, message).await {
        debug!("could not mirror the fatal error: {e}");
        return;
    }
    let _ = wr.shutdown().await;
}

async fn init_async<R, W>(
    init: Message,
    mut rd: R,
    mut wr: W,
    config: Config,
    registry: Registry,
) -> io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let session_id = (init.message_parameter & 0xFFFF) as u16;
    let entry = {
        let reg = registry.lock().await;
        reg.get(&session_id).cloned()
    };
    let entry = match entry {
        Some(e) => e,
        None => {
            send_fatal(
                &mut wr,
                FatalErrorCode::InvalidInitialization,
                format!("unknown session id {session_id}"),
            )
            .await?;
            return Ok(());
        }
    };

    {
        let mut bound = entry.async_bound.lock().await;
        if *bound {
            drop(bound);
            send_fatal(
                &mut wr,
                FatalErrorCode::InvalidInitialization,
                "async channel already bound for this session",
            )
            .await?;
            return Ok(());
        }
        *bound = true;
    }

    debug!(session_id, "hislip async initialized");

    let resp_ctrl = AsyncInitializeResponseControl::new(false);
    let resp_param = AsyncInitializeResponseParameter::new(config.vendor_id);
    MessageType::AsyncInitializeResponse
        .message_params(resp_ctrl.0, resp_param.0)
        .no_payload()
        .write_to(&mut wr)
        .await?;
    wr.flush().await?;

    async_loop(&mut rd, wr, entry, config).await
}

struct RegistrationGuard {
    id: u16,
    registry: Registry,
    locks: Arc<LockRegistry>,
}

impl Drop for RegistrationGuard {
    fn drop(&mut self) {
        // Locks go first, and synchronously: a client that crashes holding one
        // would otherwise lock the instrument out until the daemon restarts.
        // The lock registry uses a std mutex precisely so this works from Drop.
        self.locks.release_all(lock::hislip_id(self.id));

        let id = self.id;
        let registry = self.registry.clone();
        // Remove the entry in a detached task; Drop is sync but the mutex
        // is async. `try_lock` would race with a concurrent async-channel
        // init, so spawn a cleanup instead.
        tokio::spawn(async move {
            registry.lock().await.remove(&id);
        });
    }
}

/// Something the reader task lifted off the synchronous channel, or the reason
/// it stopped trying.
enum Inbound {
    Message(Message),
    /// A malformed message. Fatal ones also end the reader.
    Protocol(super::errors::Error),
    /// The socket went away, including the ordinary end-of-stream a client
    /// produces by hanging up.
    Closed(io::Error),
}

/// How many parsed messages the reader may run ahead of execution.
///
/// Any depth at all is what makes §3.1.1 rule 1 answerable: "is there data in
/// the server input queue?" cannot be asked of bytes still sitting in a socket
/// buffer, so the queue has to exist in this process. It stays small because
/// TCP is the better place to absorb a flood, and because a client that is this
/// far ahead of us in synchronized mode is about to be told so.
const SYNC_INBOX_DEPTH: usize = 32;

/// Parse the synchronous channel into `tx`, ahead of whoever is executing.
///
/// Split out into its own task rather than read inline because
/// `Message::read_from` is not cancel-safe, so it cannot be raced against
/// anything in a `select!` — and because the executor spends most of a
/// transaction inside a GPIB operation, which is exactly when a pipelining
/// client's next message arrives and needs to be *noticed*.
async fn sync_reader<R>(mut rd: R, tx: mpsc::Sender<Inbound>, maxlen: u64)
where
    R: tokio::io::AsyncRead + Unpin,
{
    loop {
        let (item, stop) = match Message::read_from(&mut rd, maxlen).await {
            Ok(Ok(m)) => (Inbound::Message(m), false),
            Ok(Err(e)) => {
                let fatal = e.is_fatal();
                (Inbound::Protocol(e), fatal)
            }
            Err(e) => (Inbound::Closed(e), true),
        };
        if tx.send(item).await.is_err() || stop {
            return;
        }
    }
}

/// The executor's view of the reader's output: a channel plus everything
/// already pulled out of it.
///
/// The local queue exists so that "has the client sent more?" can be answered
/// without consuming the answer — `try_recv` is destructive, and the message
/// that proves an exchange was interrupted still has to be executed afterwards.
struct Inbox {
    rx: mpsc::Receiver<Inbound>,
    queued: VecDeque<Inbound>,
}

impl Inbox {
    async fn next(&mut self) -> Option<Inbound> {
        match self.queued.pop_front() {
            Some(item) => Some(item),
            None => self.rx.recv().await,
        }
    }

    /// Take everything the reader has finished parsing, without blocking.
    fn drain_ready(&mut self) {
        while let Ok(item) = self.rx.try_recv() {
            self.queued.push_back(item);
        }
    }

    /// The MessageID of the first queued message that counts as input for
    /// §3.1.1 rule 1. Control traffic does not: the rule is about a query
    /// arriving before its predecessor's response was taken.
    fn pending_data_message_id(&self) -> Option<u32> {
        self.queued.iter().find_map(|item| match item {
            Inbound::Message(m)
                if matches!(
                    m.message_type,
                    MessageType::Data | MessageType::DataEnd | MessageType::Trigger
                ) =>
            {
                Some(m.message_parameter)
            }
            _ => None,
        })
    }
}

/// Drive the synchronous channel.
///
/// The writer is shared rather than owned because §6.2 has a desync reported on
/// *both* channels, and the async channel is the one that may detect it. The
/// lock is taken per write and never held across a wait for the bus or for a
/// lock, so a fatal arriving from the other side is never stuck behind a long
/// GPIB transaction or, worse, behind a client waiting out someone else's lock.
async fn sync_loop<R, W>(
    rd: R,
    writer: &Arc<Mutex<W>>,
    entry: Arc<SessionEntry>,
    config: Config,
) -> io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin,
{
    let (tx, rx) = mpsc::channel(SYNC_INBOX_DEPTH);
    let _reader = TaskGuard(tokio::spawn(sync_reader(rd, tx, config.max_message_size)));
    let mut inbox = Inbox {
        rx,
        queued: VecDeque::new(),
    };

    let mut buffer: Vec<u8> = Vec::new();
    // Snapshot of the device-clear counter, so an interrupted message can be
    // told apart from a completed one.
    let mut epoch = entry.clear_epoch.load(Ordering::Acquire);
    // §6.12 steps 5-6: between the clear and DeviceClearComplete the server
    // accepts and ignores synchronous traffic, while still requiring it to be
    // well formed — which the reader enforces either way.
    let mut discarding = false;
    loop {
        // A device clear since the last message means any half-assembled one
        // is void; the client will start again after the handshake.
        let current = entry.clear_epoch.load(Ordering::Acquire);
        if current != epoch {
            epoch = current;
            buffer.clear();
            discarding = true;
        }

        let msg = match inbox.next().await {
            None => return Ok(()),
            Some(Inbound::Closed(e)) => return Err(e),
            Some(Inbound::Message(m)) => m,
            Some(Inbound::Protocol(e)) => {
                let fatal = e.is_fatal();
                // §6.2: a desync is reported on both channels, then the
                // connection closes. The async channel has its own writer, so
                // hand it over rather than reaching across.
                if let super::errors::Error::Fatal(code, ref message) = e {
                    entry.mirror_fatal(code, message);
                }
                {
                    let mut wr = writer.lock().await;
                    Message::from(e).write_to(&mut *wr).await?;
                    wr.flush().await?;
                }
                if fatal {
                    // Give the mirrored copy a moment to reach the wire before
                    // this task returns and tears the session down.
                    tokio::time::sleep(FATAL_MIRROR_GRACE).await;
                    return Ok(());
                }
                continue;
            }
        };

        if discarding
            && !matches!(
                msg.message_type,
                MessageType::DeviceClearComplete | MessageType::FatalError
            )
        {
            debug!(?msg.message_type, "dropped during device clear");
            continue;
        }

        // Data, DataEND and Trigger all carry the RMT-delivered flag and a
        // MessageID, which §6.14 needs regardless of what the message does.
        if matches!(
            msg.message_type,
            MessageType::Data | MessageType::DataEnd | MessageType::Trigger
        ) {
            entry.note_client_message(&msg);
        }

        match msg.message_type {
            MessageType::Data | MessageType::DataEnd => {
                let is_end = msg.message_type == MessageType::DataEnd;
                buffer.extend_from_slice(&msg.payload);
                if !is_end {
                    continue;
                }
                let cmd = std::mem::take(&mut buffer);
                // Locked out? Wait, do not refuse. §2.6.1 leaves synchronous
                // traffic unprocessed until the lock frees; there is no
                // "resource locked" reply in HiSLIP and inventing one shows the
                // client a hard failure where the spec calls for a wait.
                //
                // The message has already been read off the socket, which the
                // spec would leave buffered. That is deliberate and not
                // observable: the sync channel is strictly ordered, so nothing
                // else could be serviced meanwhile either way — and having read
                // it, a client that gives up and disconnects is noticed at once
                // instead of leaving this task parked on a lock it no longer
                // wants.
                entry.wait_for_access().await;
                let expect_response = query_hint(&cmd);
                debug!(
                    "exec ({} bytes, expect_response={}): {}",
                    cmd.len(),
                    expect_response,
                    escape_bytes(&cmd)
                );
                let executed = match entry.device.execute(&cmd, expect_response).await {
                    Ok(r) => {
                        match &r.data {
                            Some(data) => {
                                debug!("resp ({} bytes): {}", data.len(), escape_bytes(data))
                            }
                            None => debug!("resp: (write-only, no read attempted)"),
                        }
                        r
                    }
                    Err(e) => {
                        warn!(
                            "device execute failed for cmd ({} bytes, expect_response={}) {:?}: {e:#}",
                            cmd.len(),
                            expect_response,
                            escape_bytes_truncated(&cmd, 120),
                        );
                        send_nonfatal(
                            &mut *writer.lock().await,
                            NonFatalErrorCode::UnidentifiedError,
                            format!("device error: {e}"),
                        )
                        .await?;
                        entry.note_message_processed(epoch, msg.message_parameter);
                        continue;
                    }
                };

                // §6.12: a clear that landed while the bus was busy abandons
                // the reply rather than delivering an answer to a question the
                // client has already withdrawn.
                if entry.clear_epoch.load(Ordering::Acquire) != epoch {
                    debug!("device clear overtook this response; abandoning it");
                    continue;
                }

                if let Some(data) = executed.data {
                    inbox.drain_ready();
                    // §3.1.1 rule 1: in synchronized mode a response may only
                    // be terminated with the input queue empty. It is not, so
                    // this exchange was interrupted: the response is thrown
                    // away and both halves of §6.11 go out instead.
                    let interrupting = match entry.mode() {
                        Mode::Synchronized => inbox.pending_data_message_id(),
                        Mode::Overlapped => None,
                    };
                    match interrupting {
                        Some(id) => {
                            warn!(
                                message_id = id,
                                "interrupted: a message arrived before the previous \
                                 response was terminated; discarding the response"
                            );
                            entry.raise_interrupted(id);
                            let mut wr = writer.lock().await;
                            MessageType::Interrupted
                                .message_params(0, id)
                                .no_payload()
                                .write_to(&mut *wr)
                                .await?;
                            wr.flush().await?;
                        }
                        None => {
                            // §6.14.1: MAV goes true as the first Data/DataEND
                            // of the response is sent, and stays true until the
                            // client says it has consumed it. Nothing to do
                            // with `*SRE`.
                            entry.mav.store(true, Ordering::Release);
                            write_response(
                                &mut *writer.lock().await,
                                &entry,
                                msg.message_parameter,
                                &data,
                            )
                            .await?;
                            entry.note_rmt_sent();
                        }
                    }
                }
                // Raised after the reply is on the wire: a client woken by the
                // service request finds the data already waiting for it.
                if let Some(stb) = executed.service_request {
                    entry.raise_service_request(stb);
                }
                entry.note_message_processed(epoch, msg.message_parameter);
            }
            MessageType::Trigger => {
                entry.wait_for_access().await;
                if let Err(e) = entry.device.trigger().await {
                    warn!("trigger failed: {e:#}");
                }
                entry.note_message_processed(epoch, msg.message_parameter);
            }
            MessageType::DeviceClearComplete => {
                // §6.12.1 step 3: the client has stated what it wants and both
                // modes are implemented, so its request is simply granted and
                // echoed back as the value in force from here on.
                let requested = FeatureBitmap(msg.control_code);
                let mode = Mode::from_overlapped(requested.overlapped());
                entry.set_mode(mode);
                let agreed = FeatureBitmap::new(mode == Mode::Overlapped, false, false);
                debug!(session = entry.id, ?mode, "device clear complete");
                discarding = false;
                buffer.clear();
                {
                    let mut wr = writer.lock().await;
                    MessageType::DeviceClearAcknowledge
                        .message_params(agreed.0, 0)
                        .no_payload()
                        .write_to(&mut *wr)
                        .await?;
                    wr.flush().await?;
                }
            }
            MessageType::FatalError => {
                warn!(
                    "client fatal: {:?}",
                    from_utf8(&msg.payload).unwrap_or("<non-utf8>")
                );
                return Ok(());
            }
            MessageType::Error => {
                warn!(
                    "client non-fatal: {:?}",
                    from_utf8(&msg.payload).unwrap_or("<non-utf8>")
                );
            }
            MessageType::StartTLS
            | MessageType::EndTLS
            | MessageType::GetSaslMechanismList
            | MessageType::AuthenticationStart
            | MessageType::AuthenticationExchange
                if entry.protocol >= super::protocol::PROTOCOL_2_0 =>
            {
                entry.mirror_fatal(
                    FatalErrorCode::SecureConnectionFailed,
                    "TLS/SASL not supported",
                );
                send_fatal(
                    &mut *writer.lock().await,
                    FatalErrorCode::SecureConnectionFailed,
                    "TLS/SASL not supported",
                )
                .await?;
                tokio::time::sleep(FATAL_MIRROR_GRACE).await;
                return Ok(());
            }
            other => {
                send_nonfatal(
                    &mut *writer.lock().await,
                    NonFatalErrorCode::UnrecognizedMessageType,
                    format!("unexpected sync message: {other:?}"),
                )
                .await?;
            }
        }
    }
}

/// Smallest response chunk we will send, whatever the client declared. A
/// client whose maximum leaves no useful room after the 16-byte header is
/// misconfigured rather than genuinely constrained, and honouring it literally
/// would mean either an infinite stream of one-byte messages or a panic on a
/// zero-length chunk.
const MIN_CHUNK: u64 = 256;

/// Push a reply on the sync channel, split so that no message — header
/// included — exceeds the maximum the client declared with AsyncMaxMsgSize.
/// The client states its own limit in that request; the response states ours.
async fn write_response<W>(
    wr: &mut W,
    entry: &SessionEntry,
    message_id: u32,
    data: &[u8],
) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let client_max = *entry.client_max_message_size.lock().await;
    let max = client_max
        .saturating_sub(Message::MESSAGE_HEADER_SIZE as u64)
        .max(MIN_CHUNK) as usize;

    // §3.1.1 stamps a reply with the id of the client message whose eom
    // produced it — legal on every chunk here, because that eom is at the end
    // of the message it identifies. §3.2.1 has the server run its own counter
    // instead, advanced once per message sent.
    let overlapped = entry.mode() == Mode::Overlapped;
    let next_id = || {
        if overlapped {
            entry.next_server_message_id()
        } else {
            message_id
        }
    };

    // An empty reply is still a reply: the client is waiting for a DataEND and
    // gets one, rather than blocking until its timeout.
    if data.is_empty() {
        MessageType::DataEnd
            .message_params(0, next_id())
            .no_payload()
            .write_to(wr)
            .await?;
        return wr.flush().await;
    }

    let mut chunks = data.chunks(max).peekable();
    while let Some(chunk) = chunks.next() {
        let ty = if chunks.peek().is_none() {
            MessageType::DataEnd
        } else {
            MessageType::Data
        };
        ty.message_params(0, next_id())
            .with_payload(chunk.to_vec())
            .write_to(wr)
            .await?;
    }
    wr.flush().await
}

/// Aborts a per-session forwarder task when the async channel goes away.
struct TaskGuard(tokio::task::JoinHandle<()>);

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Forward bus service requests to the client as `AsyncServiceRequest`.
///
/// On notification we serial-poll to learn the status byte, which the HiSLIP
/// message carries and which the poll also clears, so the device stops
/// asserting SRQ. Only a status with RQS set is forwarded: SRQ is a wired-OR
/// across the whole bus, so without that check another instrument pulling the
/// line would raise a spurious service request against this session's device.
///
/// The poll runs with no lock held. A serial poll is a bus transaction that can
/// take up to the GPIB timeout, and holding the write lock across it would stall
/// the async channel's replies for that whole time for no reason.
///
/// This is safe in either order, contrary to what an earlier revision of this
/// comment claimed: `Device::get_status` takes the bus mutex and drops it before
/// returning, so nothing is ever held across the two acquisitions and there is
/// no hold-and-wait cycle to deadlock on.
/// Poll this session's device for a service request, retrying while the SRQ
/// line stays asserted. `None` means this session has nothing to forward.
///
/// One poll per notification is not enough. A notification is an *edge*, but
/// SRQ is a wired-OR *level*: when a second device asserts while the first is
/// still holding the line low, there is no edge, so no notification, and its
/// request would never be seen. Observed on a two-instrument bus, where two
/// devices asked for service at almost the same moment and only the one that
/// happened to assert first was ever reported.
///
/// So while the line is still asserted, keep asking — either our device is
/// about to raise RQS, or somebody else's request is outstanding.
///
/// The retry is bounded. The line can legitimately stay low forever: a device
/// with no session bound to it can request service that nothing will ever
/// clear, and that must not turn into a busy loop.
async fn poll_for_service_request(entry: &SessionEntry) -> Option<u8> {
    let deadline = std::time::Instant::now() + SRQ_RECHECK_BUDGET;
    loop {
        match entry.device.get_status().await {
            Ok(stb) if stb & STB_RQS != 0 => return Some(stb),
            Ok(stb) => {
                // Not ours — at least not yet.
                match entry.device.srq_asserted().await {
                    Ok(true) if std::time::Instant::now() < deadline => {
                        tokio::time::sleep(SRQ_RECHECK_INTERVAL).await;
                    }
                    Ok(true) => {
                        debug!(
                            stb,
                            "srq still asserted after {:?}; another device is holding it \
                             and no session here can clear it",
                            SRQ_RECHECK_BUDGET
                        );
                        return None;
                    }
                    Ok(false) => {
                        debug!(stb, "srq released, nothing to forward");
                        return None;
                    }
                    // No level read available: fall back to the single poll
                    // this function used to do.
                    Err(e) => {
                        debug!(stb, "cannot read the srq line ({e:#}), not forwarding");
                        return None;
                    }
                }
            }
            Err(e) => {
                warn!("srq raised but serial poll failed, not forwarding: {e:#}");
                return None;
            }
        }
    }
}

async fn srq_forwarder<W>(
    mut srq: tokio::sync::broadcast::Receiver<()>,
    writer: Arc<Mutex<W>>,
    entry: Arc<SessionEntry>,
) where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::sync::broadcast::error::RecvError;
    loop {
        match srq.recv().await {
            Ok(()) => {}
            // SRQ is a level, not a count: coalescing missed notifications
            // into one poll loses nothing.
            Err(RecvError::Lagged(n)) => debug!("srq notifications lagged by {n}"),
            Err(RecvError::Closed) => return,
        }

        let Some(stb) = poll_for_service_request(&entry).await else {
            continue;
        };
        // That poll took RQS from the instrument, so remember it for the
        // client's next status query.
        *entry.consumed_stb.lock().unwrap() = Some(stb);

        // Bound only the *acquisition*, and only to log: abandoning a wait for
        // a lock costs nothing, so a slow acquisition is reported and then
        // waited out rather than dropping the service request. The write below
        // is deliberately not bounded — cancelling it part-way would leave a
        // truncated HiSLIP message on the socket and desync the client for
        // good, which is far worse than blocking.
        let mut guard = loop {
            match tokio::time::timeout(WRITE_LOCK_STUCK_AFTER, writer.lock()).await {
                Ok(guard) => break guard,
                Err(_) => warn!(
                    "srq forwarder has waited {:?} for the write lock; \
                     the async channel may be stuck",
                    WRITE_LOCK_STUCK_AFTER
                ),
            }
        };

        debug!(stb, "forwarding service request");
        let write = async {
            MessageType::AsyncServiceRequest
                .message_params(stb, 0)
                .no_payload()
                .write_to(&mut *guard)
                .await?;
            (*guard).flush().await
        };
        if let Err(e) = write.await {
            debug!("srq forward failed, client likely gone: {e}");
            return;
        }
    }
}

/// Push the service requests the server raises on its own behalf.
///
/// These have no SRQ line behind them, so there is nothing to serial-poll and
/// nothing to clear: the status byte is decided by whoever queued it. Today
/// that is the sync loop announcing MAV for a reply it has just delivered,
/// which the instrument cannot announce itself because the read that produced
/// the reply is what cleared its MAV bit.
async fn async_pusher<W>(mut rx: mpsc::Receiver<AsyncPush>, writer: Arc<Mutex<W>>)
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    while let Some(push) = rx.recv().await {
        let mut guard = writer.lock().await;
        let result = match push {
            AsyncPush::ServiceRequest(stb) => {
                debug!(stb, "raising service request on the server's own behalf");
                let write = async {
                    MessageType::AsyncServiceRequest
                        .message_params(stb, 0)
                        .no_payload()
                        .write_to(&mut *guard)
                        .await?;
                    (*guard).flush().await
                };
                write.await
            }
            AsyncPush::Interrupted(message_id) => {
                debug!(message_id, "reporting interrupted on the async channel");
                let write = async {
                    MessageType::AsyncInterrupted
                        .message_params(0, message_id)
                        .no_payload()
                        .write_to(&mut *guard)
                        .await?;
                    (*guard).flush().await
                };
                write.await
            }
            AsyncPush::Fatal(code, message) => {
                debug!("mirroring a fatal error onto the async channel");
                send_fatal(&mut *guard, code, message).await
            }
        };
        if let Err(e) = result {
            debug!("async push failed, client likely gone: {e}");
            return;
        }
    }
}

/// Apply one `AsyncRemoteLocalControl` request, per HiSLIP §6.7 (Table 25), in
/// the spec's own names, which line up one-to-one with VISA's RENLineOperation:
///
///   0 disableRemote          drop REN; every device goes local
///   1 enableRemote           assert REN, address nobody
///   2 disableAndGTL          GTL to this device, then drop REN
///   3 enableAndGotoRemote    assert REN and address this device
///   4 enableAndLockoutLocal  assert REN, then LLO
///   5 enableAndGTRLLO        assert REN, address, then LLO
///   6 justGTL                GTL to this device, REN untouched
///
/// Asserting REN only *permits* remote; a device enters it when addressed to
/// listen, which is why 3 and 5 do more than 1. GTL is addressed, so 2 and 6
/// return this one instrument to its front panel rather than the whole bus. LLO
/// is universal and has no per-device form — the standard offers none.
///
/// `None` for a control code outside the table.
async fn apply_remote_local(device: &dyn Device, control_code: u8) -> Option<Result<()>> {
    let res = match control_code {
        0 => device.set_remote(false).await,
        1 => device.set_remote(true).await,
        2 => match device.go_to_local().await {
            Ok(()) => device.set_remote(false).await,
            Err(e) => Err(e),
        },
        3 => device.go_to_remote().await,
        4 => match device.set_remote(true).await {
            Ok(()) => device.local_lockout().await,
            Err(e) => Err(e),
        },
        5 => match device.go_to_remote().await {
            Ok(()) => device.local_lockout().await,
            Err(e) => Err(e),
        },
        6 => device.go_to_local().await,
        _ => return None,
    };
    Some(res)
}

/// Async-channel work held back until the synchronous channel has acted on a
/// message the client named.
///
/// Run off the async read loop, not inline, because both of these can wait
/// arbitrarily long — the named message may itself be parked on a lock another
/// client holds — and §6.5.1 requires an `AsyncDeviceClear` to still be
/// answered promptly while an unlock is pending. Blocking the loop would make
/// the one escape hatch from that wait unreachable.
#[derive(Debug)]
enum Deferred {
    /// §6.7: a remote/local request that overtook the message it names.
    RemoteLocal { control_code: u8, after: u32 },
    /// §6.5.1: the MessageID on a release names the last message to complete
    /// before the lock actually drops.
    Unlock { after: u32 },
}

/// Depth of the deferred queue. §6.5.1 has clients keep one lock transaction
/// outstanding at a time, so anything beyond a couple of entries means a client
/// is not following the protocol rather than that the server is behind.
const DEFERRED_QUEUE_DEPTH: usize = 8;

async fn deferred_worker<W>(
    mut rx: mpsc::Receiver<Deferred>,
    writer: Arc<Mutex<W>>,
    entry: Arc<SessionEntry>,
) where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    while let Some(job) = rx.recv().await {
        let result = match job {
            Deferred::RemoteLocal {
                control_code,
                after,
            } => {
                if entry.wait_for_message(after).await == Awaited::Cleared {
                    debug!(after, "a device clear took the message this remote/local was waiting for");
                }
                // Acted on either way: REN and lockout are bus state, not part
                // of what a device clear rewinds, and the client asked for it.
                if let Some(Err(e)) = apply_remote_local(&*entry.device, control_code).await {
                    warn!("deferred remote/local failed: {e:#}");
                }
                let mut guard = writer.lock().await;
                write_and_flush(
                    &mut *guard,
                    MessageType::AsyncRemoteLocalResponse.message_params(0, 0),
                )
                .await
            }
            Deferred::Unlock { after } => {
                let aborted = entry.wait_for_message(after).await == Awaited::Cleared;
                let answer = entry
                    .locks
                    .release(&entry.resource, lock::hislip_id(entry.id));
                debug!(session = entry.id, ?answer, aborted, "deferred lock release");
                if aborted {
                    // §6.5.1: a device clear abandons the unlock's confirmation
                    // but not the release itself.
                    continue;
                }
                let mut guard = writer.lock().await;
                write_and_flush(
                    &mut *guard,
                    MessageType::AsyncLockResponse.message_params(answer.control_code(), 0),
                )
                .await
            }
        };
        if let Err(e) = result {
            debug!("deferred async reply failed, client likely gone: {e}");
            return;
        }
    }
}

async fn write_and_flush<W>(wr: &mut W, msg: Message) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    msg.no_payload().write_to(wr).await?;
    wr.flush().await
}

async fn async_loop<R, W>(
    rd: &mut R,
    wr: W,
    entry: Arc<SessionEntry>,
    config: Config,
) -> io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let writer = Arc::new(Mutex::new(wr));

    // Push service requests from a separate task: the loop below spends most
    // of its life parked in a read, and `Message::read_from` is not
    // cancel-safe, so it cannot be raced against the SRQ channel in a select.
    let _srq_task = match entry.device.subscribe_srq().await {
        Some(rx) => Some(TaskGuard(tokio::spawn(srq_forwarder(
            rx,
            writer.clone(),
            entry.clone(),
        )))),
        None => {
            debug!("adapter cannot report SRQ; bus service requests will not be pushed");
            None
        }
    };

    // The other source: service requests the server raises itself. Separate
    // task for the same reason — the loop below is parked in a read almost all
    // of the time.
    let _push_task = entry
        .async_rx
        .lock()
        .await
        .take()
        .map(|rx| TaskGuard(tokio::spawn(async_pusher(rx, writer.clone()))));

    // Anything §6.5.1 or §6.7 makes wait on the synchronous channel runs here,
    // in order, so the read loop below stays free to answer a device clear.
    let (deferred_tx, deferred_rx) = mpsc::channel(DEFERRED_QUEUE_DEPTH);
    let _deferred_task = TaskGuard(tokio::spawn(deferred_worker(
        deferred_rx,
        writer.clone(),
        entry.clone(),
    )));

    loop {
        // Read with the writer unlocked, so the forwarder can push meanwhile.
        let incoming = Message::read_from(rd, config.max_message_size).await?;

        // A contended lock request waits for the holder to let go, which can be
        // the client's whole timeout. Do that before taking the write lock:
        // parking this client is what it asked for, parking the service-request
        // forwarders behind it is not.
        let mut lock_answer = None;
        if let Ok(msg) = &incoming {
            if msg.message_type == MessageType::AsyncLock && msg.control_code != 0 {
                let lock_string = String::from_utf8_lossy(&msg.payload).into_owned();
                let timeout = Duration::from_millis(msg.message_parameter as u64);
                let answer = entry
                    .locks
                    .request(
                        &entry.resource,
                        lock::hislip_id(entry.id),
                        &lock_string,
                        timeout,
                    )
                    .await;
                debug!(
                    session = entry.id,
                    %lock_string,
                    ?timeout,
                    ?answer,
                    "lock request"
                );
                lock_answer = Some(answer);
            }
        }

        let mut guard = writer.lock().await;
        let wr = &mut *guard;

        let msg = match incoming {
            Ok(m) => m,
            Err(e) => {
                let fatal = e.is_fatal();
                // §6.2, the other direction: report it on the sync channel too.
                if let super::errors::Error::Fatal(code, ref message) = e {
                    entry.mirror_fatal_to_sync(code, message);
                }
                Message::from(e).write_to(wr).await?;
                wr.flush().await?;
                if fatal {
                    tokio::time::sleep(FATAL_MIRROR_GRACE).await;
                    return Ok(());
                }
                continue;
            }
        };

        match msg.message_type {
            MessageType::AsyncLock => {
                // Control code 0 releases, 1 requests. A request was answered
                // above, before the write lock.
                let answer = match lock_answer {
                    Some(answer) => answer,
                    None => {
                        // §6.5.1: the MessageID names the last message that has
                        // to complete before the lock drops. Usually it already
                        // has, and the release is immediate.
                        let after = msg.message_parameter;
                        if !entry.message_processed(after) {
                            match deferred_tx.try_send(Deferred::Unlock { after }) {
                                Ok(()) => {
                                    debug!(
                                        session = entry.id,
                                        after, "holding the lock release until that message completes"
                                    );
                                    continue;
                                }
                                Err(_) => warn!(
                                    "deferred queue full; releasing the lock without waiting"
                                ),
                            }
                        }
                        let answer = entry
                            .locks
                            .release(&entry.resource, lock::hislip_id(entry.id));
                        debug!(session = entry.id, ?answer, "lock release");
                        answer
                    }
                };
                MessageType::AsyncLockResponse
                    .message_params(answer.control_code(), 0)
                    .no_payload()
                    .write_to(wr)
                    .await?;
                wr.flush().await?;
            }
            MessageType::AsyncLockInfo => {
                let (exclusive, holders) = entry.locks.info(&entry.resource);
                MessageType::AsyncLockInfoResponse
                    .message_params(u8::from(exclusive), holders)
                    .no_payload()
                    .write_to(wr)
                    .await?;
                wr.flush().await?;
            }
            MessageType::AsyncMaximumMessageSize => {
                if msg.payload.len() != 8 {
                    send_fatal(
                        wr,
                        FatalErrorCode::PoorlyFormattedMessageHeader,
                        "AsyncMaximumMessageSize payload must be 8 bytes",
                    )
                    .await?;
                    return Ok(());
                }
                let size = NetworkEndian::read_u64(&msg.payload);
                *entry.client_max_message_size.lock().await = size;
                let mut buf = [0u8; 8];
                NetworkEndian::write_u64(&mut buf, config.max_message_size);
                MessageType::AsyncMaximumMessageSizeResponse
                    .message_params(0, 0)
                    .with_payload(buf.to_vec())
                    .write_to(wr)
                    .await?;
                wr.flush().await?;
            }
            MessageType::AsyncDeviceClear => {
                // §2.6.1: a client without the lock still gets its device clear,
                // and gets it immediately — but it clears only this session.
                // Touching the bus would reach straight past somebody else's
                // lock, and waiting for that lock would strand the one escape
                // §6.5.1 gives a pending unlock.
                //
                // The reset lands before the bus operation: the sync loop
                // compares the epoch across its own work, so it has to change
                // while that work is still running for the reply to be dropped.
                entry.reset_for_device_clear();
                if entry.has_access() {
                    // The GpibController serializes ops across the shared
                    // Arc<Mutex<_>>, so this clear is naturally ordered after
                    // whatever the sync side is mid-doing — no explicit
                    // cross-channel signal needed.
                    if let Err(e) = entry.device.clear().await {
                        warn!("device clear failed: {e:#}");
                    }
                } else {
                    debug!(
                        session = entry.id,
                        "another client holds the lock; clearing this session only"
                    );
                }
                // §6.12.1 step 1: the server states what it would prefer, and
                // the client answers in DeviceClearComplete.
                let features = FeatureBitmap::new(config.prefer_overlap, false, false);
                MessageType::AsyncDeviceClearAcknowledge
                    .message_params(features.0, 0)
                    .no_payload()
                    .write_to(wr)
                    .await?;
                wr.flush().await?;
            }
            MessageType::AsyncRemoteLocalControl => {
                if msg.control_code > 6 {
                    send_nonfatal(
                        wr,
                        NonFatalErrorCode::UnrecognizedControlCode,
                        format!("unknown remote/local code {}", msg.control_code),
                    )
                    .await?;
                    continue;
                }
                // §6.7: the two channels can reorder, so a request that names a
                // message the sync side has not reached yet waits for it rather
                // than acting out of order.
                let after = msg.message_parameter;
                if !entry.message_processed(after) {
                    let job = Deferred::RemoteLocal {
                        control_code: msg.control_code,
                        after,
                    };
                    match deferred_tx.try_send(job) {
                        Ok(()) => {
                            debug!(after, "holding remote/local until that message completes");
                            continue;
                        }
                        Err(_) => warn!("deferred queue full; acting on remote/local now"),
                    }
                }
                // §6.7 again: the response goes out after the action, but never
                // waits on a lock another client holds.
                if let Some(Err(e)) = apply_remote_local(&*entry.device, msg.control_code).await {
                    warn!("remote/local failed: {e:#}");
                }
                MessageType::AsyncRemoteLocalResponse
                    .message_params(0, 0)
                    .no_payload()
                    .write_to(wr)
                    .await?;
                wr.flush().await?;
            }
            MessageType::AsyncStatusQuery => {
                // A status query is one of the messages carrying RMT-delivered,
                // and for a client that only polls it is the *only* way it ever
                // says it took the response (§6.14.1, §3.1.1 rule 2).
                if RmtDeliveredControl(msg.control_code).rmt_delivered() {
                    entry.note_rmt_delivered();
                }
                // HiSLIP has no error reply for a status query — the response
                // carries a status byte and nothing else — so a failed poll can
                // only be reported as 0. Log it, so it is at least visible as a
                // failure rather than passing for a genuine "nothing to report".
                let mut stb = match entry.device.get_status().await {
                    Ok(stb) => stb,
                    Err(e) => {
                        warn!("hislip status query failed, reporting 0: {e:#}");
                        0
                    }
                };
                // If the instrument has nothing to report, it may be because
                // the daemon already took it: a serial poll clears RQS, and
                // the daemon has to poll to fill in an AsyncServiceRequest.
                // Hand that byte over rather than let the client read a bit
                // that was consumed on its behalf. Only when the live poll is
                // silent, so a real reading is never overwritten.
                if stb == 0 {
                    if let Some(consumed) = entry.take_consumed_stb() {
                        debug!(consumed, "reporting the status byte we polled earlier");
                        stb = consumed;
                    }
                } else {
                    entry.take_consumed_stb();
                }
                // MAV is the server's to report, not the instrument's: the read
                // that fetched the reply cleared the instrument's own bit, and
                // §6.14.1 defines MAV by message flow anyway. Overwrite bit 4
                // in whatever came back rather than OR-ing, so a stale set bit
                // cannot outlive the response it belonged to.
                stb = (stb & !STB_MAV) | entry.mav_bit(msg.message_parameter);
                MessageType::AsyncStatusResponse
                    .message_params(stb, 0)
                    .no_payload()
                    .write_to(wr)
                    .await?;
                wr.flush().await?;
            }
            MessageType::AsyncStartTLS | MessageType::AsyncEndTLS
                if entry.protocol >= super::protocol::PROTOCOL_2_0 =>
            {
                send_fatal(
                    wr,
                    FatalErrorCode::SecureConnectionFailed,
                    "TLS not supported",
                )
                .await?;
                return Ok(());
            }
            MessageType::FatalError => {
                warn!(
                    "client fatal (async): {:?}",
                    from_utf8(&msg.payload).unwrap_or("<non-utf8>")
                );
                return Ok(());
            }
            MessageType::Error => {
                warn!(
                    "client non-fatal (async): {:?}",
                    from_utf8(&msg.payload).unwrap_or("<non-utf8>")
                );
            }
            other => {
                send_nonfatal(
                    wr,
                    NonFatalErrorCode::UnrecognizedMessageType,
                    format!("unexpected async message: {other:?}"),
                )
                .await?;
            }
        }
    }
}

/// Parse a HiSLIP subaddress into an optional GPIB primary address.
///
/// Supported forms:
/// - `hislip<N>` / `gpib<N>` / `inst<N>` — trailing digits are the PAD
/// - `<N>` — bare numeric subaddress
/// - `foo,N` / `foo:N` — explicit separator form (PAD is after the last
///   separator). Note: most VISA clients collapse `foo,N` into
///   `sub_address=foo, port=N` before the string ever reaches us, so
///   clients typically want the no-separator form.
///
/// The literal `hislip0` and `gpib0` stay reserved for "use the
/// daemon-configured default PAD" so existing scripts that treat
/// `TCPIP::host::hislip0::INSTR` as a generic handle still work.
pub fn parse_subaddress_pad(sub: &str) -> Option<u8> {
    let s = sub.trim().trim_end_matches('\0');
    if s.is_empty() || s.eq_ignore_ascii_case("hislip0") || s.eq_ignore_ascii_case("gpib0") {
        return None;
    }
    let tail = s.rsplit([',', ':']).next().unwrap_or(s);
    let digits: String = tail
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    if digits.is_empty() {
        return None;
    }
    if let Ok(n) = digits.parse::<u8>() {
        if n <= 30 {
            return Some(n);
        }
    }
    None
}

/// Render bytes as a single-line string with non-printable bytes escaped as
/// `\xNN`. Common control characters get C-style escapes (`\n \r \t \\`) so
/// SCPI traffic stays readable in the log. Used by the `-v` HiSLIP cmd/response
/// dump.
fn escape_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            b'\t' => s.push_str("\\t"),
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    s
}

/// Whether a command looks like a query: a `?` *outside* string literals.
///
/// This is a hint, not the decision — the device's `execute` asks the
/// instrument itself (MAV in the status byte) whether output is pending, so a
/// missed query here still gets its response read. What the hint controls is
/// the expensive path: blocking on an addressed read that nothing will answer.
/// `DISP:TEXT "why?"` must not look like a query, or a valid command reports a
/// timeout — observed, not theoretical.
///
/// SCPI string literals are single- or double-quoted, and a doubled quote
/// inside is an escape. The scan does not need to understand the escape: `""`
/// reads as close-then-reopen, which keeps the text between quotes either way.
/// An unterminated literal quotes the rest of the message, which errs toward
/// "not a query" — the MAV check downstream covers it.
pub fn query_hint(cmd: &[u8]) -> bool {
    let mut quote: Option<u8> = None;
    for &b in cmd {
        match quote {
            Some(q) => {
                if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'?' => return true,
                _ => {}
            },
        }
    }
    false
}

fn escape_bytes_truncated(bytes: &[u8], max: usize) -> String {
    if bytes.len() <= max {
        escape_bytes(bytes)
    } else {
        let mut s = escape_bytes(&bytes[..max]);
        s.push_str(&format!("… (+{} bytes)", bytes.len() - max));
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NullDevice;

    #[async_trait::async_trait]
    impl Device for NullDevice {
        async fn execute(&self, _cmd: &[u8], _expect_response: bool) -> Result<Execution> {
            Ok(Execution::default())
        }
        async fn trigger(&self) -> Result<()> {
            Ok(())
        }
        async fn clear(&self) -> Result<()> {
            Ok(())
        }
        async fn set_remote(&self, _remote: bool) -> Result<()> {
            Ok(())
        }
        async fn get_status(&self) -> Result<u8> {
            Ok(0)
        }
    }

    fn session(mode: Mode) -> SessionEntry {
        SessionEntry::new(
            0,
            SUPPORTED_PROTOCOL,
            Arc::new(NullDevice),
            Arc::new(LockRegistry::new()),
            1024,
            mode == Mode::Overlapped,
        )
    }

    /// The id a client quotes before it has sent anything, and straight after a
    /// device clear (§6.14).
    const INITIAL_QUOTED_ID: u32 = FIRST_MESSAGE_ID.wrapping_sub(2);

    fn client_message(ty: MessageType, message_id: u32, rmt_delivered: bool) -> Message {
        ty.message_params(u8::from(rmt_delivered), message_id)
            .no_payload()
    }

    #[test]
    fn synchronized_mav_follows_message_flow() {
        let s = session(Mode::Synchronized);
        assert_eq!(s.mav_bit(INITIAL_QUOTED_ID), 0);

        s.note_client_message(&client_message(MessageType::DataEnd, FIRST_MESSAGE_ID, false));
        s.mav.store(true, Ordering::Release);
        assert_eq!(s.mav_bit(FIRST_MESSAGE_ID), STB_MAV);
        // §6.14.3: a query quoting anything but the latest message is told no.
        assert_eq!(s.mav_bit(INITIAL_QUOTED_ID), 0);

        s.note_rmt_delivered();
        assert_eq!(s.mav_bit(FIRST_MESSAGE_ID), 0);
    }

    #[test]
    fn overlapped_mav_compares_message_ids() {
        let s = session(Mode::Overlapped);
        // Nothing sent yet, so the id the client must quote is the initial one.
        assert_eq!(s.mav_bit(INITIAL_QUOTED_ID), 0);

        assert_eq!(s.next_server_message_id(), FIRST_MESSAGE_ID);
        // That message is out but unacknowledged.
        assert_eq!(s.mav_bit(INITIAL_QUOTED_ID), STB_MAV);
        assert_eq!(s.mav_bit(FIRST_MESSAGE_ID), 0);

        assert_eq!(s.next_server_message_id(), FIRST_MESSAGE_ID.wrapping_add(2));
        assert_eq!(s.mav_bit(FIRST_MESSAGE_ID), STB_MAV);
    }

    #[test]
    fn overlapped_mav_ignores_the_message_flow_state() {
        let s = session(Mode::Overlapped);
        // §6.14.2 is purely a MessageID comparison; the synchronized-mode flag
        // must not leak into it.
        s.mav.store(true, Ordering::Release);
        assert_eq!(s.mav_bit(INITIAL_QUOTED_ID), 0);
    }

    #[test]
    fn matching_rmt_flags_clear_the_expectation() {
        let s = session(Mode::Synchronized);
        s.note_rmt_sent();
        assert!(s.rmt_expected.load(Ordering::Acquire));

        s.note_client_message(&client_message(MessageType::Data, FIRST_MESSAGE_ID, true));
        assert!(!s.rmt_expected.load(Ordering::Acquire));
    }

    #[test]
    fn a_disagreeing_rmt_flag_leaves_the_expectation_standing() {
        let s = session(Mode::Synchronized);
        s.note_rmt_sent();
        // The interrupted error §3.1.1 rule 2 describes is reported inside the
        // server only, so the expectation stays up for the message that will
        // eventually acknowledge it.
        s.note_client_message(&client_message(MessageType::Data, FIRST_MESSAGE_ID, false));
        assert!(s.rmt_expected.load(Ordering::Acquire));
    }

    #[test]
    fn overlapped_mode_does_not_track_rmt() {
        let s = session(Mode::Overlapped);
        s.note_rmt_sent();
        s.note_client_message(&client_message(MessageType::Data, FIRST_MESSAGE_ID, true));
        assert!(s.rmt_expected.load(Ordering::Acquire));
    }

    #[test]
    fn device_clear_rewinds_both_message_id_counters() {
        let s = session(Mode::Overlapped);
        s.next_server_message_id();
        s.note_client_message(&client_message(MessageType::DataEnd, FIRST_MESSAGE_ID, false));
        s.mav.store(true, Ordering::Release);
        s.note_rmt_sent();
        let epoch = s.clear_epoch.load(Ordering::Acquire);

        s.reset_for_device_clear();

        assert_eq!(s.mav_bit(INITIAL_QUOTED_ID), 0);
        assert_eq!(s.next_server_message_id(), FIRST_MESSAGE_ID);
        assert_eq!(
            s.last_message_id.load(Ordering::Acquire),
            INITIAL_QUOTED_ID
        );
        assert!(!s.rmt_expected.load(Ordering::Acquire));
        // The epoch has to move, or the sync loop keeps a voided response.
        assert_ne!(s.clear_epoch.load(Ordering::Acquire), epoch);
    }

    #[test]
    fn the_mode_survives_a_round_trip_through_the_feature_bitmap() {
        let s = session(Mode::Synchronized);
        let requested = FeatureBitmap::new(true, false, false);
        s.set_mode(Mode::from_overlapped(requested.overlapped()));
        assert_eq!(s.mode(), Mode::Overlapped);

        let requested = FeatureBitmap::new(false, false, false);
        s.set_mode(Mode::from_overlapped(requested.overlapped()));
        assert_eq!(s.mode(), Mode::Synchronized);
    }

    #[test]
    fn a_wrapped_message_id_is_still_ordered() {
        // Plain `>=` would get all three of these backwards.
        assert!(message_reached(2, u32::MAX - 2));
        assert!(!message_reached(u32::MAX - 2, 2));
        assert!(message_reached(FIRST_MESSAGE_ID, FIRST_MESSAGE_ID));
        assert!(!message_reached(
            FIRST_MESSAGE_ID,
            FIRST_MESSAGE_ID.wrapping_add(2)
        ));
        assert!(message_reached(
            FIRST_MESSAGE_ID,
            FIRST_MESSAGE_ID.wrapping_sub(2)
        ));
    }

    #[test]
    fn the_id_quoted_before_anything_is_sent_counts_as_reached() {
        // Otherwise the release and remote/local a client sends straight after
        // Initialize would both defer on a message that never existed.
        let s = session(Mode::Synchronized);
        assert!(s.message_processed(INITIAL_QUOTED_ID));
        assert!(!s.message_processed(FIRST_MESSAGE_ID));
    }

    #[tokio::test]
    async fn a_wait_ends_when_the_named_message_is_acted_on() {
        let s = Arc::new(session(Mode::Synchronized));
        let epoch = s.clear_epoch.load(Ordering::Acquire);

        let waiter = tokio::spawn({
            let s = s.clone();
            async move { s.wait_for_message(FIRST_MESSAGE_ID).await }
        });
        tokio::task::yield_now().await;

        s.note_message_processed(epoch, FIRST_MESSAGE_ID);
        assert_eq!(waiter.await.unwrap(), Awaited::Processed);
    }

    #[tokio::test]
    async fn a_device_clear_abandons_a_wait() {
        let s = Arc::new(session(Mode::Synchronized));

        let waiter = tokio::spawn({
            let s = s.clone();
            async move { s.wait_for_message(FIRST_MESSAGE_ID).await }
        });
        tokio::task::yield_now().await;

        s.reset_for_device_clear();
        assert_eq!(waiter.await.unwrap(), Awaited::Cleared);
    }

    #[tokio::test]
    async fn a_watermark_from_before_a_clear_does_not_resurrect_a_wait() {
        let s = Arc::new(session(Mode::Synchronized));
        let stale = s.clear_epoch.load(Ordering::Acquire);
        s.reset_for_device_clear();

        // The sync loop was mid-message when the clear landed; its report
        // arrives afterwards and must not move the rewound watermark.
        s.note_message_processed(stale, FIRST_MESSAGE_ID);
        assert!(!s.message_processed(FIRST_MESSAGE_ID));
    }

    #[test]
    fn only_data_traffic_counts_as_a_pending_interruption() {
        let (tx, rx) = mpsc::channel(4);
        let mut inbox = Inbox {
            rx,
            queued: VecDeque::new(),
        };
        // Control traffic in the queue is not the interrupted condition: §3.1.1
        // rule 1 is about a query arriving before its predecessor was read.
        tx.try_send(Inbound::Message(
            MessageType::DeviceClearComplete
                .message_params(0, 0)
                .no_payload(),
        ))
        .unwrap();
        tx.try_send(Inbound::Message(client_message(
            MessageType::DataEnd,
            FIRST_MESSAGE_ID,
            false,
        )))
        .unwrap();

        inbox.drain_ready();
        assert_eq!(inbox.pending_data_message_id(), Some(FIRST_MESSAGE_ID));
    }

    #[test]
    fn an_empty_inbox_is_not_an_interruption() {
        let (_tx, rx) = mpsc::channel(4);
        let mut inbox = Inbox {
            rx,
            queued: VecDeque::new(),
        };
        inbox.drain_ready();
        assert_eq!(inbox.pending_data_message_id(), None);
    }

    #[test]
    fn query_hint_finds_ordinary_queries() {
        assert!(query_hint(b"*IDN?"));
        assert!(query_hint(b"MEAS:VOLT:DC?"));
        assert!(query_hint(b":SYST:ERR?\n"));
        assert!(query_hint(b"CONF:VOLT:DC 10; :READ?"));
    }

    #[test]
    fn query_hint_ignores_question_marks_inside_strings() {
        assert!(!query_hint(b"DISP:TEXT \"why?\""));
        assert!(!query_hint(b"DISP:TEXT 'why?'"));
        // Doubled-quote escape keeps the text quoted.
        assert!(!query_hint(b"DISP:TEXT \"he said \"\"what?\"\"\""));
    }

    #[test]
    fn query_hint_sees_queries_next_to_strings() {
        assert!(query_hint(b"DISP:TEXT \"ready\"; *OPC?"));
        // A quote character of the other kind inside a literal does not close it.
        assert!(query_hint(b"DISP:TEXT 'a \"b'; *ESR?"));
    }

    #[test]
    fn query_hint_plain_commands_are_not_queries() {
        assert!(!query_hint(b"*RST"));
        assert!(!query_hint(b"SYST:REM"));
        // Unterminated literal errs toward "not a query".
        assert!(!query_hint(b"DISP:TEXT \"oops?"));
    }

    #[test]
    fn parse_pad() {
        // pyvisa-compatible no-separator forms
        assert_eq!(parse_subaddress_pad("hislip14"), Some(14));
        assert_eq!(parse_subaddress_pad("hislip16"), Some(16));
        assert_eq!(parse_subaddress_pad("gpib7"), Some(7));
        assert_eq!(parse_subaddress_pad("inst3"), Some(3));
        // bare numeric
        assert_eq!(parse_subaddress_pad("14"), Some(14));
        // explicit-separator forms (for clients that don't strip commas)
        assert_eq!(parse_subaddress_pad("gpib0,14"), Some(14));
        assert_eq!(parse_subaddress_pad("hislip0,7"), Some(7));
        // reserved defaults
        assert_eq!(parse_subaddress_pad("hislip0"), None);
        assert_eq!(parse_subaddress_pad("gpib0"), None);
        assert_eq!(parse_subaddress_pad(""), None);
        // out of range
        assert_eq!(parse_subaddress_pad("gpib0,31"), None);
        assert_eq!(parse_subaddress_pad("hislip31"), None);
    }

    #[test]
    fn standard_port_is_4880() {
        assert_eq!(super::super::STANDARD_PORT, 4880);
    }

    #[test]
    fn escape_keeps_printable_and_escapes_controls() {
        assert_eq!(escape_bytes(b"*IDN?"), "*IDN?");
        assert_eq!(escape_bytes(b"hi\nthere\r\n"), "hi\\nthere\\r\\n");
        assert_eq!(escape_bytes(b"tab\there"), "tab\\there");
        assert_eq!(escape_bytes(b"back\\slash"), "back\\\\slash");
        // 0x01 is non-printable, no shortcut → \x01
        assert_eq!(escape_bytes(&[0x01, b'A', 0xff]), "\\x01A\\xff");
        // 0x7e (~) is the last printable, 0x7f (DEL) is not
        assert_eq!(escape_bytes(&[0x7e, 0x7f]), "~\\x7f");
    }

    #[test]
    fn escape_truncated_appends_suffix() {
        assert_eq!(escape_bytes_truncated(b"abcdef", 10), "abcdef");
        assert_eq!(escape_bytes_truncated(b"abcdef", 6), "abcdef");
        assert_eq!(escape_bytes_truncated(b"abcdefghij", 4), "abcd… (+6 bytes)");
    }
}
