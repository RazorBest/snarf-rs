pub mod deque;
pub mod ipv4_util;
pub mod tcp;
pub mod tcp_util;
pub mod util;

use std::collections::HashMap;
use std::error::Error;
use std::hash::Hash;
use std::mem;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::BytesMut;
use etherparse::{
    InternetSlice::{Ipv4, Ipv6},
    SlicedPacket,
};
use tokio::io::unix::AsyncFd;

use crate::ipv4_util::ipv4_checksum;
use crate::tcp::{TCP_DSTPORT_OFFSET, TCP_SRCPORT_OFFSET, TcpSession};
use crate::tcp_util::{TCP_DATAOFFSET_IDX, TCP_SEQ_OFFSET};

pub enum SnarfInterceptVerdict<RF> {
    Accept(RF),
    Drop(RF),
    Keep,
}

pub enum InterceptVerdict {
    Accept,
    Drop,
    Keep,
}

pub trait NetworkSnarfHandler<RF> {
    fn on_payload(&mut self, rf: RF) -> Vec<SnarfInterceptVerdict<RF>>;
}

pub trait TransportSnarfHandler<NetAddr, RF> {
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
    pub fn new_from_handler(
        opts: &SnarfNfqNetOptions,
        net_handler: NetHandler,
    ) -> Result<Self, Box<dyn Error>> {
        let mut queue = nfq::Queue::open()?;
        queue.bind(opts.queue_num)?;
        queue.set_nonblocking(true);

        let async_fd = AsyncFd::new(queue.as_raw_fd())?;

        Ok(Self {
            queue,
            async_fd,
            net_handler,
        })
    }

    async fn get_next_msg(&mut self) -> Result<nfq::Message, Box<dyn Error>> {
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

    pub async fn intercept(&mut self, running: Arc<AtomicBool>) -> Result<(), Box<dyn Error>> {
        while running.load(Ordering::SeqCst) {
            let running_clone = running.clone();
            let while_running = async move {
                while running_clone.load(Ordering::SeqCst) {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                }
            };
            let mut msg = tokio::select! {
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

            // let net_payload = msg.get_payload_mut();
            let mut payload = BytesMut::new();
            mem::swap(&mut msg.payload, &mut payload);

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
        // TODO: One drawback with these rules is that they don't catch the first SYN packet of an inbound connection.
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
                    let new_checksum = ipv4_checksum(
                        tcp_payload,
                        ip_header[12..16].try_into().unwrap(),
                        ip_header[16..20].try_into().unwrap(),
                    );
                    tcp_payload[16..18].copy_from_slice(&new_checksum.to_be_bytes());

                    self.net_spy
                        .after(ip_header, tcp_payload, &InterceptVerdict::Accept);

                    SnarfInterceptVerdict::Accept(rf.message)
                }
                SnarfInterceptVerdict::Drop(mut rf) => {
                    let (net_header, tcp_payload) = rf.split();
                    self.net_spy
                        .after(net_header, tcp_payload, &InterceptVerdict::Drop);

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
}

pub trait TransportPacketParent {
    /// Splits into an immutable network header reference and a mutable tcp payload (including data)
    /// reference
    fn split(&mut self) -> (&[u8], &mut [u8]);
}

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
    NetAddr: Copy + Hash + Ord + Default,
    TSpy: TransportSnarfSpy,
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
        let (net_header, tcp_payload) = rf.split();
        let src_port = u16::from_be_bytes([
            tcp_payload[TCP_SRCPORT_OFFSET],
            tcp_payload[TCP_SRCPORT_OFFSET + 1],
        ]);
        let dst_port = u16::from_be_bytes([
            tcp_payload[TCP_DSTPORT_OFFSET],
            tcp_payload[TCP_DSTPORT_OFFSET + 1],
        ]);
        let header_len = (tcp_payload[TCP_DATAOFFSET_IDX] >> 4) as usize * 4;

        if self.sessions.map.len() > 1000 {
            panic!("Too many sessions");
        }

        let src_addr = TcpAddr::new(src_net, src_port);
        let dst_addr = TcpAddr::new(dst_net, dst_port);
        self.last_used_key = Some((src_addr, dst_addr));
        let &mut TcpSessionWithId {
            ref mut session,
            session_id,
        } = self.sessions.get_session(src_addr, dst_addr);

        let (tcp_header, data) = tcp_payload[..].split_at(header_len);
        self.transport_spy
            .before(net_header, tcp_header, data, session_id);

        let (is_client, retransmitted, writable, _) = session
            .read_tcp_packet(src_net, src_port, tcp_payload)
            .unwrap();
        self.last_is_client = is_client;

        let (tcp_header, data) = tcp_payload[..].split_at_mut(header_len);

        // If packet is from future
        if writable.is_none() && retransmitted == 0 && !data.is_empty() {
            session.add_future_payload(is_client, rf);
            return vec![SnarfInterceptVerdict::Keep];
        }

        if let Some(mut writable) = writable {
            let mut seq = u32::from_be_bytes([
                tcp_header[TCP_SEQ_OFFSET],
                tcp_header[TCP_SEQ_OFFSET + 1],
                tcp_header[TCP_SEQ_OFFSET + 2],
                tcp_header[TCP_SEQ_OFFSET + 3],
            ]);
            seq = seq.wrapping_add(retransmitted as u32);

            let new_data = &mut data[retransmitted..];

            self.app_data_handler
                .on_data(session_id, is_client, seq as i64, new_data);
            writable.copy_from_slice(new_data);
        }

        self.transport_spy.after(
            net_header,
            tcp_header,
            is_client,
            data,
            session_id,
            &InterceptVerdict::Accept,
        );

        let mut verdicts = self.transport_packet_verdict_kept();

        verdicts.insert(0, SnarfInterceptVerdict::Accept(rf));

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
