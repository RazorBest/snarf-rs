//! Framework for building MitM applications.
//!
//! Skip the nasty stuff. Get visibility.
//!
pub mod deque;
pub mod ipv4_util;
pub mod tcp;
pub mod tcp_util;
pub mod util;

use std::collections::HashMap;
use std::error::Error;
use std::hash::Hash;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use etherparse::{
    InternetSlice::{Ipv4, Ipv6},
    SlicedPacket,
};
use tokio::io::unix::AsyncFd;

use crate::tcp::{SnarfTcpError, TcpSession};
use crate::tcp_util::{
    TCP_DSTPORT_OFFSET, TCP_SEQ_OFFSET, TCP_SRCPORT_OFFSET, tcp_header_len,
    update_checksum_tcp_ipv4,
};

pub enum SnarfInterceptVerdict<RF> {
    Accept(RF),
    Drop(RF),
    Keep,
}

#[derive(Clone)]
pub enum InterceptVerdict {
    Accept,
    Drop,
}

pub trait NetworkSnarfHandler<RF> {
    fn on_payload(&mut self, rf: RF) -> Vec<SnarfInterceptVerdict<RF>>;
}

pub trait TransportSnarfHandler<NetAddr, RF> {
    /*
     * Handles a TCP packet. Must guarantee that the packet is eventually
     * returned back in the verdict vector after subsequent calls.*/
    fn on_transport_packet(
        &mut self,
        src_ip: NetAddr,
        dst_ip: NetAddr,
        rf: RF,
    ) -> Vec<SnarfInterceptVerdict<RF>>;
}

pub trait ApplicationDataSnarfHandler {
    fn on_data(
        &mut self,
        session_id: u64,
        is_client: bool,
        counter: i64,
        data: &mut [u8],
    ) -> InterceptVerdict;
}

#[derive(Default)]
pub struct NoSpy;

pub trait NetworkSnarfSpy {
    fn before(&mut self, net_header: &[u8], data: &[u8]);
    fn after(&mut self, net_header: &[u8], data: &[u8], verdict: &InterceptVerdict);
}

impl NetworkSnarfSpy for NoSpy {
    fn before(&mut self, _net_header: &[u8], _data: &[u8]) {}
    fn after(&mut self, _net_header: &[u8], _data: &[u8], _verdict: &InterceptVerdict) {}
}

pub trait TransportSnarfSpy {
    fn before(&mut self, net_header: &[u8], transport_header: &[u8], data: &[u8], session_id: u64);
    fn after(
        &mut self,
        net_header: &[u8],
        transport_header: &[u8],
        is_client: bool,
        data: &[u8],
        session_id: u64,
        verdict: &InterceptVerdict,
    );
    fn close(&mut self, is_client: bool, session_id: u64);
}

impl TransportSnarfSpy for NoSpy {
    fn before(
        &mut self,
        _net_header: &[u8],
        _transport_header: &[u8],
        _data: &[u8],
        _session_id: u64,
    ) {
    }
    fn after(
        &mut self,
        _net_header: &[u8],
        _transport_header: &[u8],
        _is_client: bool,
        _data: &[u8],
        _session_id: u64,
        _verdict: &InterceptVerdict,
    ) {
    }
    fn close(&mut self, _is_client: bool, _session_id: u64) {}
}

#[derive(Clone)]
pub struct SnarfNfqNetOptions {
    queue_num: u16,
}

impl SnarfNfqNetOptions {
    pub fn open_from_handler<NetHandler>(
        &self,
        net_handler: NetHandler,
    ) -> Result<SnarfNfqNet<NetHandler>, Box<dyn Error>>
    where
        NetHandler: NetworkSnarfHandler<nfq::Message>,
    {
        SnarfNfqNet::new_from_handler(self, net_handler)
    }

    pub fn open<NetHandler>(&self) -> Result<SnarfNfqNet<NetHandler>, Box<dyn Error>>
    where
        NetHandler: NetworkSnarfHandler<nfq::Message> + Default,
    {
        SnarfNfqNet::new_from_handler(self, NetHandler::default())
    }
}

pub struct SnarfNfqNet<NetHandler>
where
    NetHandler: NetworkSnarfHandler<nfq::Message>,
{
    pub queue: nfq::Queue,
    pub async_fd: AsyncFd<RawFd>,
    pub net_handler: NetHandler,
}

impl<NetHandler> SnarfNfqNet<NetHandler>
where
    NetHandler: NetworkSnarfHandler<nfq::Message>,
{
    /// Creates a new `Self` instance from `NetHandler`.
    ///
    /// # Arguments
    ///
    /// * `opts` - Configuration options.
    /// * `net_handler` - An instance that handles network packets.
    pub fn new_from_handler(
        opts: &SnarfNfqNetOptions,
        net_handler: NetHandler,
    ) -> Result<Self, Box<dyn Error>> {
        let mut queue = nfq::Queue::open()?;
        queue.bind(opts.queue_num)?;
        queue.set_nonblocking(true);
        queue.set_copy_range(opts.queue_num, u16::MAX)?;

        let async_fd = AsyncFd::new(queue.as_raw_fd())?;

        Ok(Self {
            queue,
            async_fd,
            net_handler,
        })
    }

    async fn get_next_msg(&mut self) -> Result<nfq::Message, Box<dyn Error + Send + Sync>> {
        loop {
            let mut guard = self.async_fd.readable().await?;

            match self.queue.recv() {
                Ok(msg) => {
                    return Ok(msg);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                }
                Err(err) => {
                    return Err(err.into());
                }
            }
        }
    }

    pub fn get_next_msg_blocking(&mut self) -> Result<nfq::Message, Box<dyn Error>> {
        match self.queue.recv() {
            Ok(msg) => Ok(msg),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                panic!("queue would block");
            }
            Err(err) => Err(err.into()),
        }
    }

    async fn verdict(&mut self, msg: nfq::Message) -> Result<(), Box<dyn Error>> {
        let mut _guard = self.async_fd.writable().await?;

        match self.queue.verdict(msg) {
            Ok(msg) => Ok(msg),
            Err(err) => Err(err.into()),
        }
    }

    pub fn verdict_blocking(&mut self, msg: nfq::Message) -> Result<(), Box<dyn Error>> {
        Ok(self.queue.verdict(msg)?)
    }

    async fn wait_for_verdict(
        &mut self,
        running: Arc<AtomicBool>,
        msg: nfq::Message,
    ) -> Result<(), Box<dyn Error>> {
        tokio::select! {
            ret = self.verdict(msg) => {
                ret?;
            },
            _ = tokio::spawn(async move {
                while running.load(Ordering::SeqCst) {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                }
            }) => (),
        }

        Ok(())
    }

    pub async fn intercept(
        &mut self,
        running: Arc<AtomicBool>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        while running.load(Ordering::SeqCst) {
            let running_clone = running.clone();
            let while_running = async move {
                while running_clone.load(Ordering::SeqCst) {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                }
            };
            let msg = tokio::select! {
                msg = self.get_next_msg() => {
                    msg
                },
                _ = tokio::spawn(while_running) => {
                    // Trigger when `running` is set to false
                    return Ok(());
                },
            }?;

            {
                let payload_len = msg.get_payload().len();
                let original_len = msg.get_original_len();
                if payload_len != original_len {
                    println!("len / original: {} / {}", payload_len, original_len);
                    panic!("Packet was truncated");
                }
            }

            let verdicts = self.net_handler.on_payload(msg);

            for vd in verdicts {
                let msg = match vd {
                    SnarfInterceptVerdict::Accept(mut msg) => {
                        msg.set_verdict(nfq::Verdict::Accept);

                        msg
                    }
                    SnarfInterceptVerdict::Drop(mut msg) => {
                        msg.set_verdict(nfq::Verdict::Drop);

                        msg
                    }
                    _ => {
                        continue;
                    }
                };

                self.wait_for_verdict(running.clone(), msg).await.unwrap();
            }
        }

        Ok(())
    }
}

type Ipv4Type = [u8; 4];

#[derive(Default)]
pub struct SnarfNfqIpv4<TH, NetSpy>
where
    TH: TransportSnarfHandler<Ipv4Type, NfqMessageParent>,
    NetSpy: NetworkSnarfSpy,
{
    transport_handler: TH,
    net_spy: NetSpy,
}

impl<TH, NetSpy> SnarfNfqIpv4<TH, NetSpy>
where
    TH: TransportSnarfHandler<Ipv4Type, NfqMessageParent>,
    NetSpy: NetworkSnarfSpy,
{
    pub fn new(transport_handler: TH, net_spy: NetSpy) -> Self {
        Self {
            transport_handler,
            net_spy,
        }
    }
}

impl<NetSpy, TH> NetworkSnarfHandler<nfq::Message> for SnarfNfqIpv4<TH, NetSpy>
where
    TH: TransportSnarfHandler<Ipv4Type, NfqMessageParent>,
    NetSpy: NetworkSnarfSpy,
{
    fn on_payload(&mut self, mut rf: nfq::Message) -> Vec<SnarfInterceptVerdict<nfq::Message>> {
        let payload = rf.get_payload_mut();
        let Ok(parsed) = SlicedPacket::from_ip(payload) else {
            return vec![SnarfInterceptVerdict::Accept(rf)];
        };

        let (src_ip, dst_ip, ip_header_len) = match &parsed.net {
            Some(Ipv4(ip)) => {
                let header = ip.header();

                (
                    header.source(),
                    header.destination(),
                    (header.ihl() * 4) as usize,
                )
            }
            Some(Ipv6(..)) => {
                panic!("IPv6 is not supported");
            }
            _ => {
                panic!("Non-IP packet");
            }
        };
        drop(parsed);

        let (ip_header, tcp_payload) = payload.split_at(ip_header_len);
        self.net_spy.before(ip_header, tcp_payload);

        let msg_parent = NfqMessageParent {
            message: rf,
            ip_header_len,
        };
        let verdicts = self
            .transport_handler
            .on_transport_packet(src_ip, dst_ip, msg_parent);

        let mut upstream_verdicts = vec![];

        for verdict in verdicts {
            let up_verdict = match verdict {
                SnarfInterceptVerdict::Accept(mut rf) => {
                    let (ip_header, tcp_payload) = rf.split();
                    update_checksum_tcp_ipv4(ip_header, tcp_payload);
                    self.net_spy
                        .after(ip_header, tcp_payload, &InterceptVerdict::Accept);

                    SnarfInterceptVerdict::Accept(rf.message)
                }
                SnarfInterceptVerdict::Drop(mut rf) => {
                    let (ip_header, tcp_payload) = rf.split();
                    self.net_spy
                        .after(ip_header, tcp_payload, &InterceptVerdict::Drop);

                    SnarfInterceptVerdict::Drop(rf.message)
                }
                SnarfInterceptVerdict::Keep => SnarfInterceptVerdict::Keep,
            };

            upstream_verdicts.push(up_verdict);
        }

        upstream_verdicts
    }
}

#[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct TcpAddr<NetAddr: Copy + Hash + Ord + Default> {
    pub net: NetAddr,
    pub port: u16,
}

impl<NetAddr: Copy + Hash + Ord + Default> TcpAddr<NetAddr> {
    fn new(net: NetAddr, port: u16) -> Self {
        TcpAddr { net, port }
    }
}

type NetAddrPair<NetAddr> = (TcpAddr<NetAddr>, TcpAddr<NetAddr>);

#[derive(Debug)]
pub struct TcpSessionWithId<NetAddr, RF>
where
    NetAddr: Copy + Hash + Ord + Default,
    RF: TransportPacketParent,
{
    pub session: TcpSession<NetAddr, RF>,
    pub session_id: u64,
}

impl<NetAddr, RF> TcpSessionWithId<NetAddr, RF>
where
    NetAddr: Copy + Hash + Ord + Default,
    RF: TransportPacketParent,
{
    pub fn new(session_id: u64) -> Self {
        Self {
            session: TcpSession::default(),
            session_id,
        }
    }
}

#[derive(Debug, Default)]
pub struct TcpSessionMap<NetAddr, RF>
where
    NetAddr: Copy + Hash + Ord + Default,
    RF: TransportPacketParent,
{
    map: HashMap<NetAddrPair<NetAddr>, TcpSessionWithId<NetAddr, RF>>,
    id_counter: u64,
}

impl<NetAddr, RF> TcpSessionMap<NetAddr, RF>
where
    NetAddr: Copy + Hash + Ord + Default,
    RF: TransportPacketParent,
{
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            id_counter: 0,
        }
    }

    pub fn get_session(
        &mut self,
        src_addr: TcpAddr<NetAddr>,
        dst_addr: TcpAddr<NetAddr>,
    ) -> &mut TcpSessionWithId<NetAddr, RF> {
        // Sort them
        let key = if src_addr < dst_addr {
            (src_addr, dst_addr)
        } else {
            (dst_addr, src_addr)
        };

        self.map.entry(key).or_insert_with(|| {
            let session_id = self.id_counter;
            self.id_counter += 1;

            TcpSessionWithId::new(session_id)
        })
    }

    pub fn remove_session(
        &mut self,
        src_addr: TcpAddr<NetAddr>,
        dst_addr: TcpAddr<NetAddr>,
    ) -> Option<TcpSessionWithId<NetAddr, RF>> {
        // Sort them
        let key = if src_addr < dst_addr {
            (src_addr, dst_addr)
        } else {
            (dst_addr, src_addr)
        };

        self.map.remove(&key)
    }
}

pub trait TransportPacketParent {
    /// Splits into an immutable network header reference and a mutable transport payload (including data)
    /// reference
    fn split(&mut self) -> (&[u8], &mut [u8]);
}

#[derive(Debug)]
pub struct NfqMessageParent {
    pub message: nfq::Message,
    pub ip_header_len: usize,
}

impl TransportPacketParent for NfqMessageParent {
    fn split(&mut self) -> (&[u8], &mut [u8]) {
        let payload = self.message.get_payload_mut();
        let (net_header, tcp_payload) = payload.split_at_mut(self.ip_header_len);

        (net_header, tcp_payload)
    }
}

#[derive(Debug, Default)]
pub struct SnarfTcp<AH, TSpy, NetAddr, RF>
where
    AH: ApplicationDataSnarfHandler,
    TSpy: TransportSnarfSpy,
    NetAddr: Copy + Hash + Ord + Default,
    RF: TransportPacketParent,
{
    pub sessions: TcpSessionMap<NetAddr, RF>,
    pub transport_spy: TSpy,
    pub app_data_handler: AH,
    pub last_used_key: Option<(TcpAddr<NetAddr>, TcpAddr<NetAddr>)>,
    pub last_is_client: bool,
}

impl<AH, TSpy, NetAddr, RF> SnarfTcp<AH, TSpy, NetAddr, RF>
where
    AH: ApplicationDataSnarfHandler,
    TSpy: TransportSnarfSpy,
    NetAddr: Copy + Hash + Ord + Default,
    RF: TransportPacketParent,
{
    pub fn new_from(app_data_handler: AH, transport_spy: TSpy) -> Self {
        Self {
            sessions: TcpSessionMap::new(),
            transport_spy,
            app_data_handler,
            last_used_key: None,
            last_is_client: false,
        }
    }

    fn get_last_accessed_session(
        last_used_key: Option<(TcpAddr<NetAddr>, TcpAddr<NetAddr>)>,
        sessions: &mut TcpSessionMap<NetAddr, RF>,
    ) -> Option<&mut TcpSessionWithId<NetAddr, RF>> {
        match last_used_key {
            None => None,
            Some((src_addr, dst_addr)) => Some(sessions.get_session(src_addr, dst_addr)),
        }
    }
}

impl<NetAddr, TSpy, AH, RF> TransportSnarfHandler<NetAddr, RF> for SnarfTcp<AH, TSpy, NetAddr, RF>
where
    NetAddr: Copy + Hash + Ord + Default,
    TSpy: TransportSnarfSpy,
    AH: ApplicationDataSnarfHandler,
    RF: TransportPacketParent,
{
    fn on_transport_packet(
        &mut self,
        src_net: NetAddr,
        dst_net: NetAddr,
        mut rf: RF,
    ) -> Vec<SnarfInterceptVerdict<RF>> {
        let mut verdicts = vec![];
        let (net_header, tcp_payload) = rf.split();
        let src_port = u16::from_be_bytes([
            tcp_payload[TCP_SRCPORT_OFFSET],
            tcp_payload[TCP_SRCPORT_OFFSET + 1],
        ]);
        let dst_port = u16::from_be_bytes([
            tcp_payload[TCP_DSTPORT_OFFSET],
            tcp_payload[TCP_DSTPORT_OFFSET + 1],
        ]);
        let header_len = tcp_header_len(tcp_payload);

        let src_addr = TcpAddr::new(src_net, src_port);
        let dst_addr = TcpAddr::new(dst_net, dst_port);
        let (tcp_header, data) = tcp_payload[..].split_at(header_len);

        self.last_used_key = Some((src_addr, dst_addr));
        let result = self.sessions.get_session(src_addr, dst_addr);
        let mut session = &mut result.session;
        let mut session_id = result.session_id;

        self.transport_spy
            .before(net_header, tcp_header, data, session_id);

        let (
            mut is_client,
            mut retransmitted,
            mut writable,
            _,
            mut is_future,
            mut closing,
            new_connection,
        ) = session
            .read_tcp_packet(src_net, src_port, tcp_payload)
            .unwrap();

        if new_connection {
            verdicts.append(&mut self.drain_futures_from_last_session());
            self.sessions.remove_session(src_addr, dst_addr);

            let result = self.sessions.get_session(src_addr, dst_addr);
            session = &mut result.session;
            session_id = result.session_id;

            (is_client, retransmitted, writable, _, is_future, closing, _) = session
                .read_tcp_packet(src_net, src_port, tcp_payload)
                .unwrap();
        };

        self.last_is_client = is_client;

        let (tcp_header, data) = tcp_payload[..].split_at_mut(header_len);

        let mut remove_session = closing;
        let (mut rf, this_verdict) =
            // If packet is from future
            if is_future {
                let res = session.add_future_payload(is_client, rf);
                match res {
                    Err((rf, SnarfTcpError::FutureQueueOverflow)) => {
                        remove_session = true;
                        (rf, InterceptVerdict::Drop)
                    }
                    Err((_rf, err)) => {
                        panic!("{:?}", err);
                    }
                    _ => {
                        return vec![SnarfInterceptVerdict::Keep];
                    }
                }
            } else if let Some(mut writable) = writable {
                let mut seq = u32::from_be_bytes([
                    tcp_header[TCP_SEQ_OFFSET],
                    tcp_header[TCP_SEQ_OFFSET + 1],
                    tcp_header[TCP_SEQ_OFFSET + 2],
                    tcp_header[TCP_SEQ_OFFSET + 3],
                ]);
                seq = seq.wrapping_add(retransmitted as u32);

                let new_data = &mut data[retransmitted..];

                let this_verdict = self
                    .app_data_handler
                    .on_data(session_id, is_client, seq as i64, new_data);
                writable.copy_from_slice(new_data);

                (rf, this_verdict)
            } else {
                (rf, InterceptVerdict::Accept)
            };

        if remove_session {
            verdicts.append(&mut self.drain_futures_from_last_session());
            self.sessions.remove_session(src_addr, dst_addr);
        } else {
            verdicts.append(&mut self.transport_packet_verdict_kept());
        }

        let (net_header, tcp_payload) = rf.split();
        let header_len = tcp_header_len(tcp_payload);
        let (tcp_header, data) = tcp_payload[..].split_at(header_len);

        self.transport_spy.after(
            net_header,
            tcp_header,
            is_client,
            data,
            session_id,
            &this_verdict,
        );

        if remove_session {
            self.transport_spy.close(false, session_id);
            self.transport_spy.close(true, session_id);
        }

        match this_verdict {
            InterceptVerdict::Accept => {
                verdicts.push(SnarfInterceptVerdict::Accept(rf));
            }
            InterceptVerdict::Drop => {
                verdicts.push(SnarfInterceptVerdict::Drop(rf));
            }
        }

        verdicts
    }
}

impl<AH, TSpy, NetAddr, RF> SnarfTcp<AH, TSpy, NetAddr, RF>
where
    AH: ApplicationDataSnarfHandler,
    TSpy: TransportSnarfSpy,
    NetAddr: Copy + Hash + Ord + Default,
    RF: TransportPacketParent,
{
    fn transport_packet_verdict_kept(&mut self) -> Vec<SnarfInterceptVerdict<RF>> {
        let Some(&mut TcpSessionWithId {
            ref mut session,
            session_id,
        }) = Self::get_last_accessed_session(self.last_used_key, &mut self.sessions)
        else {
            return vec![];
        };
        let future_verdicts = session.verdict_kept(self.last_is_client);
        let mut upstream_verdicts = vec![];
        for mut vd in future_verdicts {
            let mut parent = vd.rf;
            let (net_header, tcp_payload) = parent.split();
            let header_len = vd.header_len;
            let new_data_len = vd.new_data_len;
            let old_data_len = tcp_payload.len() - header_len - new_data_len;

            let mut seq = u32::from_be_bytes([
                tcp_payload[TCP_SEQ_OFFSET],
                tcp_payload[TCP_SEQ_OFFSET + 1],
                tcp_payload[TCP_SEQ_OFFSET + 2],
                tcp_payload[TCP_SEQ_OFFSET + 3],
            ]);
            seq = seq.wrapping_add(old_data_len as u32);

            let (tcp_header, data) = tcp_payload.split_at_mut(header_len);
            let new_data = &mut data[old_data_len..];

            self.app_data_handler
                .on_data(session_id, self.last_is_client, seq as i64, new_data);
            vd.writable.copy_from_slice(new_data);

            self.transport_spy.after(
                net_header,
                tcp_header,
                self.last_is_client,
                data,
                session_id,
                &InterceptVerdict::Accept,
            );

            upstream_verdicts.push(SnarfInterceptVerdict::Accept(parent));
        }

        upstream_verdicts
    }

    fn drain_futures_from_last_session(&mut self) -> Vec<SnarfInterceptVerdict<RF>> {
        let Some(&mut TcpSessionWithId {
            ref mut session,
            session_id,
        }) = Self::get_last_accessed_session(self.last_used_key, &mut self.sessions)
        else {
            return vec![];
        };

        let mut upstream_verdicts = vec![];

        let is_client = true;
        let future_verdicts = session.drain_nowrite_future_queue(is_client);
        for vd in future_verdicts {
            let mut parent = vd.rf;
            let (net_header, tcp_payload) = parent.split();
            let header_len = vd.header_len;
            let (tcp_header, data) = tcp_payload.split_at_mut(header_len);

            self.transport_spy.after(
                net_header,
                tcp_header,
                true,
                data,
                session_id,
                &InterceptVerdict::Drop,
            );

            upstream_verdicts.push(SnarfInterceptVerdict::Drop(parent));
        }

        let is_client = false;
        let future_verdicts = session.drain_nowrite_future_queue(is_client);
        for vd in future_verdicts {
            let mut parent = vd.rf;
            let (net_header, tcp_payload) = parent.split();
            let header_len = vd.header_len;
            let (tcp_header, data) = tcp_payload.split_at_mut(header_len);

            self.transport_spy.after(
                net_header,
                tcp_header,
                is_client,
                data,
                session_id,
                &InterceptVerdict::Drop,
            );

            upstream_verdicts.push(SnarfInterceptVerdict::Drop(parent));
        }

        upstream_verdicts
    }
}

pub type SnarfNfqIpv4Tcp<AH, NetSpy, TSpy> =
    SnarfNfqNet<SnarfNfqIpv4<SnarfTcp<AH, TSpy, Ipv4Type, NfqMessageParent>, NetSpy>>;

impl<AH, NetSpy, TSpy> SnarfNfqIpv4Tcp<AH, NetSpy, TSpy>
where
    AH: ApplicationDataSnarfHandler,
    NetSpy: NetworkSnarfSpy,
    TSpy: TransportSnarfSpy,
{
    pub fn new_from_handlers(
        opts: &SnarfNfqNetOptions,
        app_handler: AH,
        net_spy: NetSpy,
        transport_spy: TSpy,
    ) -> Result<Self, Box<dyn Error>> {
        let tcp = SnarfTcp::new_from(app_handler, transport_spy);
        let ip = SnarfNfqIpv4::new(tcp, net_spy);

        SnarfNfqNet::new_from_handler(opts, ip)
    }
}

impl<AH, NetSpy, TSpy> SnarfNfqIpv4Tcp<AH, NetSpy, TSpy>
where
    AH: ApplicationDataSnarfHandler + Default,
    NetSpy: NetworkSnarfSpy + Default,
    TSpy: TransportSnarfSpy + Default,
{
    pub fn new(opts: &SnarfNfqNetOptions) -> Result<Self, Box<dyn Error>> {
        let app_handler = AH::default();
        let net_spy = NetSpy::default();
        let transport_spy = TSpy::default();
        Self::new_from_handlers(opts, app_handler, net_spy, transport_spy)
    }
}

pub struct SnarfNfqIpv4TcpOptions {
    pub queue_num: u16,
}

impl From<&SnarfNfqIpv4TcpOptions> for SnarfNfqNetOptions {
    fn from(obj: &SnarfNfqIpv4TcpOptions) -> Self {
        Self {
            queue_num: obj.queue_num,
        }
    }
}

impl SnarfNfqIpv4TcpOptions {
    pub fn open<AH, NetSpy, TSpy>(
        &self,
    ) -> Result<SnarfNfqIpv4Tcp<AH, NetSpy, TSpy>, Box<dyn Error>>
    where
        AH: ApplicationDataSnarfHandler + Default,
        NetSpy: NetworkSnarfSpy + Default,
        TSpy: TransportSnarfSpy + Default,
    {
        SnarfNfqIpv4Tcp::new(&self.into())
    }

    pub fn open_from<AH, NetSpy, TSpy>(
        &self,
        app_handler: AH,
        net_spy: NetSpy,
        transport_spy: TSpy,
    ) -> Result<SnarfNfqIpv4Tcp<AH, NetSpy, TSpy>, Box<dyn Error>>
    where
        AH: ApplicationDataSnarfHandler,
        NetSpy: NetworkSnarfSpy,
        TSpy: TransportSnarfSpy,
    {
        SnarfNfqIpv4Tcp::new_from_handlers(&self.into(), app_handler, net_spy, transport_spy)
    }
}

#[cfg(test)]
mod test_snarf_tcp {
    use super::*;
    use crate::ipv4_util::ipv4_header_len;
    use crate::tcp_util::{
        ACK_MASK, CWR_MASK, ECE_MASK, FIN_MASK, PSH_MASK, RST_MASK, SYN_MASK, URG_MASK,
    };
    use etherparse::{PacketBuilder, TcpHeader};
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct AHDummy {}
    impl ApplicationDataSnarfHandler for AHDummy {
        fn on_data(
            &mut self,
            _session_id: u64,
            _is_client: bool,
            _counter: i64,
            _data: &mut [u8],
        ) -> InterceptVerdict {
            InterceptVerdict::Accept
        }
    }

    #[allow(dead_code)]
    struct PacketEvent {
        net_header: Vec<u8>,
        transport_header: Vec<u8>,
        data: Vec<u8>,
        session_id: u64,
        // Is some when inside a SpyEvent::After or SpyEvent::Close
        is_client: Option<bool>,
        // Is some when inside a SpyEvent::After
        verdict: Option<InterceptVerdict>,
    }

    impl PacketEvent {
        fn new(
            net_header: &[u8],
            transport_header: &[u8],
            data: &[u8],
            session_id: u64,
            is_client: Option<bool>,
            verdict: Option<InterceptVerdict>,
        ) -> Self {
            Self {
                net_header: net_header.to_vec(),
                transport_header: transport_header.to_vec(),
                data: data.to_vec(),
                session_id,
                is_client,
                verdict,
            }
        }
    }

    enum SpyEvent {
        Before(PacketEvent),
        After(PacketEvent),
        Close(PacketEvent),
    }

    #[derive(Default)]
    struct TSpy {
        events: Vec<SpyEvent>,
    }

    impl TransportSnarfSpy for TSpy {
        fn before(
            &mut self,
            net_header: &[u8],
            transport_header: &[u8],
            data: &[u8],
            session_id: u64,
        ) {
            self.events.push(SpyEvent::Before(PacketEvent::new(
                net_header,
                transport_header,
                data,
                session_id,
                None,
                None,
            )));
        }
        fn after(
            &mut self,
            net_header: &[u8],
            transport_header: &[u8],
            is_client: bool,
            data: &[u8],
            session_id: u64,
            verdict: &InterceptVerdict,
        ) {
            self.events.push(SpyEvent::After(PacketEvent::new(
                net_header,
                transport_header,
                data,
                session_id,
                Some(is_client),
                Some(verdict.clone()),
            )));
        }
        fn close(&mut self, is_client: bool, session_id: u64) {
            self.events.push(SpyEvent::Close(PacketEvent::new(
                &[],
                &[],
                &[],
                session_id,
                Some(is_client),
                None,
            )));
        }
    }

    impl TransportSnarfSpy for Rc<RefCell<TSpy>> {
        fn before(
            &mut self,
            net_header: &[u8],
            transport_header: &[u8],
            data: &[u8],
            session_id: u64,
        ) {
            self.borrow_mut()
                .before(net_header, transport_header, data, session_id)
        }
        fn after(
            &mut self,
            net_header: &[u8],
            transport_header: &[u8],
            is_client: bool,
            data: &[u8],
            session_id: u64,
            verdict: &InterceptVerdict,
        ) {
            self.borrow_mut().after(
                net_header,
                transport_header,
                is_client,
                data,
                session_id,
                verdict,
            )
        }
        fn close(&mut self, is_client: bool, session_id: u64) {
            self.borrow_mut().close(is_client, session_id)
        }
    }

    struct TParent {
        id: u64,
        ip: Vec<u8>,
        tcp: Vec<u8>,
    }

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    impl TParent {
        fn new(ip: Vec<u8>, tcp: Vec<u8>) -> Self {
            Self {
                id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
                ip,
                tcp,
            }
        }
    }

    impl TransportPacketParent for TParent {
        fn split(&mut self) -> (&[u8], &mut [u8]) {
            (&self.ip, &mut self.tcp)
        }
    }

    type THandler = SnarfTcp<AHDummy, Rc<RefCell<TSpy>>, Ipv4Type, TParent>;

    fn new_transport_handler() -> THandler {
        let tspy = Rc::new(RefCell::new(TSpy::default()));
        THandler::new_from(AHDummy {}, tspy)
    }

    struct TcpConnection {
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    }

    impl TcpConnection {
        const fn new(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Self {
            Self {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            }
        }

        /// Returns the reversed connection
        fn rev(&self) -> Self {
            Self {
                src_ip: self.dst_ip,
                dst_ip: self.src_ip,
                src_port: self.dst_port,
                dst_port: self.src_port,
            }
        }

        fn get_addr(&self) -> (TcpAddr<Ipv4Type>, TcpAddr<Ipv4Type>) {
            let src_addr = TcpAddr::new(self.src_ip, self.src_port);
            let dst_addr = TcpAddr::new(self.dst_ip, self.dst_port);

            (src_addr, dst_addr)
        }
    }

    const TCP_CONNS: [TcpConnection; 4] = [
        TcpConnection::new([192, 138, 26, 100], [192, 198, 26, 100], 1024, 1024),
        TcpConnection::new([192, 138, 26, 100], [192, 138, 26, 100], 80, 123),
        TcpConnection::new([108, 138, 26, 100], [192, 198, 26, 100], 123, 124),
        TcpConnection::new([108, 138, 26, 100], [182, 198, 106, 80], 223, 224),
    ];

    fn gen_packet(
        conn: &TcpConnection,
        payload: &[u8],
        seq: u32,
        ack: Option<u32>,
        flags: u8,
    ) -> TParent {
        let ttl = 64;
        let window_size = u16::MAX;

        let mut tcp_header = TcpHeader::new(conn.src_port, conn.dst_port, seq, window_size);
        tcp_header.fin = (flags & FIN_MASK) != 0;
        tcp_header.syn = (flags & SYN_MASK) != 0;
        tcp_header.rst = (flags & RST_MASK) != 0;
        tcp_header.psh = (flags & PSH_MASK) != 0;
        tcp_header.ack = ack.is_some() || ((flags & ACK_MASK) != 0);
        tcp_header.urg = (flags & URG_MASK) != 0;
        tcp_header.ece = (flags & ECE_MASK) != 0;
        tcp_header.cwr = (flags & CWR_MASK) != 0;
        if let Some(ack) = ack {
            tcp_header.acknowledgment_number = ack;
        }

        let builder = PacketBuilder::ipv4(conn.src_ip, conn.dst_ip, ttl).tcp_header(tcp_header);

        let mut ip_packet = vec![];
        builder.write(&mut ip_packet, payload).unwrap();

        let ip_len = ipv4_header_len(&ip_packet) as usize;
        let tcp_segment = ip_packet.split_off(ip_len);

        TParent::new(ip_packet, tcp_segment)
    }

    fn packet_expect_accept(th: &mut THandler, conn: &TcpConnection, packet: TParent) {
        let packet_id = packet.id;
        let verdicts = th.on_transport_packet(conn.src_ip, conn.dst_ip, packet);
        assert!(
            !verdicts.is_empty(),
            "The tcp handler must return a verdict"
        );
        assert!(
            matches!(verdicts[0], SnarfInterceptVerdict::Accept(..)),
            "The tcp handler's verdict must be ACCEPT"
        );
        let SnarfInterceptVerdict::Accept(rf) = &verdicts[0] else {
            panic!("The tcp handler's verdict must be ACCEPT");
        };
        assert_eq!(
            rf.id, packet_id,
            "The returned verdict must be for the provided packet"
        );

        let session_id = {
            let (src, dst) = conn.get_addr();
            let res = th.sessions.get_session(src, dst);

            res.session_id
        };

        let events = &mut th.transport_spy.borrow_mut().events;
        assert!(events.len() == 2);
        let SpyEvent::Before(e) = events.remove(0) else {
            panic!("Expected 'before' event");
        };
        assert_eq!(e.session_id, session_id);
        let SpyEvent::After(e) = events.remove(0) else {
            panic!("Expected 'after' event");
        };
        assert_eq!(e.session_id, session_id);
    }

    fn packet_expect_close(th: &mut THandler, conn: &TcpConnection, packet: TParent) {
        let packet_id = packet.id;
        let session_id = {
            let (src, dst) = conn.get_addr();
            let res = th.sessions.get_session(src, dst);

            res.session_id
        };

        let verdicts = th.on_transport_packet(conn.src_ip, conn.dst_ip, packet);
        assert!(
            !verdicts.is_empty(),
            "The tcp handler must return a verdict"
        );
        assert!(
            matches!(verdicts[0], SnarfInterceptVerdict::Accept(..)),
            "The tcp handler's verdict must be ACCEPT"
        );
        let SnarfInterceptVerdict::Accept(rf) = &verdicts[0] else {
            panic!("The tcp handler's verdict must be ACCEPT");
        };
        assert_eq!(
            rf.id, packet_id,
            "The returned verdict must be for the provided packet"
        );

        let events = &mut th.transport_spy.borrow_mut().events;
        assert!(events.len() == 4);
        let SpyEvent::Before(e) = events.remove(0) else {
            panic!("Expected 'before' event");
        };
        assert_eq!(e.session_id, session_id);

        let SpyEvent::After(e) = events.remove(0) else {
            panic!("Expected 'after' event");
        };
        assert_eq!(e.session_id, session_id);

        let SpyEvent::Close(e1) = events.remove(0) else {
            panic!("Expected 'after' event");
        };
        let SpyEvent::Close(e2) = events.remove(0) else {
            panic!("Expected 'after' event");
        };
        assert_ne!(e1.is_client, e2.is_client);
        assert_eq!(e1.session_id, session_id);
        assert_eq!(e2.session_id, session_id);

        events.clear();
    }

    #[test]
    fn test_rst_after_syn() {
        let mut th = new_transport_handler();
        let conn = &TCP_CONNS[0];

        let packet = gen_packet(conn, &[], 1000, None, SYN_MASK);
        packet_expect_accept(&mut th, conn, packet);

        let packet = gen_packet(&conn.rev(), &[], 0, Some(1001), RST_MASK);
        packet_expect_close(&mut th, &conn.rev(), packet);
    }

    #[test]
    fn test_rst_after_synack() {
        let mut th = new_transport_handler();
        let conn = &TCP_CONNS[0];

        let packet = gen_packet(conn, &[], 1000, None, SYN_MASK);
        packet_expect_accept(&mut th, conn, packet);

        let packet = gen_packet(&conn.rev(), &[], 3000, Some(1001), SYN_MASK | ACK_MASK);
        packet_expect_accept(&mut th, &conn.rev(), packet);

        let packet = gen_packet(conn, &[], 1001, Some(3001), RST_MASK);
        packet_expect_close(&mut th, conn, packet);
    }

    #[test]
    fn test_rst_after_establish() {
        let mut th = new_transport_handler();
        let conn = &TCP_CONNS[0];

        let packet = gen_packet(conn, &[], 1000, None, SYN_MASK);
        packet_expect_accept(&mut th, conn, packet);

        let packet = gen_packet(&conn.rev(), &[], 3000, Some(1001), SYN_MASK | ACK_MASK);
        packet_expect_accept(&mut th, &conn.rev(), packet);

        let packet = gen_packet(conn, &[], 1001, Some(3001), ACK_MASK);
        packet_expect_accept(&mut th, conn, packet);

        let packet = gen_packet(&conn.rev(), &[], 3001, Some(1001), RST_MASK);
        packet_expect_close(&mut th, &conn.rev(), packet);
    }
}
