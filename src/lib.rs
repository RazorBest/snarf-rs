mod tcp;
mod ipv4;

use std::collections::{HashMap};
use std::error::Error;
use std::hash::Hash;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration};

use etherparse::{
    InternetSlice::{Ipv4, Ipv6},
    SlicedPacket,
};
use tokio::io::unix::AsyncFd;

use crate::tcp::{TcpSession, TCP_DATAOFFSET_IDX, TCP_SRCPORT_OFFSET, TCP_DSTPORT_OFFSET};
use crate::ipv4::ipv4_checksum;

const SRC_IPV4_OFFSET: usize = 12;
const DST_IPV4_OFFSET: usize = 16;

fn get_interface_ip(iface: &str) -> Option<Vec<u8>> {
    use nix::ifaddrs::getifaddrs;

    for ifaddr in getifaddrs().ok()? {
        if ifaddr.interface_name != iface {
            continue;
        }

        if let Some(address) = ifaddr.address {
            if let Some(ip) = address.as_sockaddr_in() {
                return Some(ip.ip().octets().to_vec());
            }

            if let Some(ip6) = address.as_sockaddr_in6() {
                return Some(ip6.ip().octets().to_vec());
            }
        }
    }

    None
}

#[derive(Clone)]
pub struct PcapPacket {
    timestamp: u64, 
    data: Vec<u8>,
}

#[derive(Debug)]
pub struct InterceptorOptions {
    // TODO: use this field to restrict interception only for this port
    pub _iface: String,
    pub queue_num: u16,
}

pub enum InterceptVerdict {
    Accept,
    Drop,
}

pub trait NetworkSnarfHandler {
    fn on_payload(&mut self, payload: &mut [u8]) -> InterceptVerdict;
}

pub trait TransportSnarfHandler<NetAddr> {
    fn on_transport_packet(
        &mut self,
        src_ip: NetAddr,
        dst_ip: NetAddr,
        tcp_payload: &mut [u8],
    ) -> InterceptVerdict;
}

pub trait ApplicationDataSnarfHandler {
    fn on_data(&mut self, is_client: bool, data: &mut [u8]) -> InterceptVerdict;
}

pub struct SnarfNfqNetOptions {
    queue_num: u16,
}

pub struct SnarfNfqNet<NetHandler>
where
    NetHandler: NetworkSnarfHandler
{
    pub queue: nfq::Queue,
    pub async_fd: AsyncFd<RawFd>,
    pub net_handler: NetHandler,
}

impl<NetHandler: NetworkSnarfHandler> SnarfNfqNet<NetHandler>
{
    fn new(opts: &SnarfNfqNetOptions, net_handler: NetHandler) -> Result<Self, Box<dyn Error>> {
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

    async fn verdict(&mut self, msg: nfq::Message) -> Result<(), Box<dyn Error>> {
        let mut _guard = self.async_fd.writable().await?;

        match self.queue.verdict(msg) {
            Ok(msg) => Ok(msg),
            Err(err) => Err(err.into()),
        }
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

    async fn live_intercept(&mut self, running: Arc<AtomicBool>) -> Result<(), Box<dyn Error>> {
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

            let net_payload = msg.get_payload_mut();

            let verdict: InterceptVerdict = self.net_handler.on_payload(net_payload);
            match verdict {
                InterceptVerdict::Accept => {
                    msg.set_verdict(nfq::Verdict::Accept);
                }
                InterceptVerdict::Drop => {
                    msg.set_verdict(nfq::Verdict::Drop);
                }
            }

            self.wait_for_verdict(running.clone(), msg).await.unwrap();
        }

        Ok(())
    }
}

type Ipv4Type = [u8; 4];

struct SnarfIpv4<TH: TransportSnarfHandler<Ipv4Type>> {
    transport_handler: TH,
}

impl<TH: TransportSnarfHandler<Ipv4Type>> NetworkSnarfHandler for SnarfIpv4<TH> {
    fn on_payload(&mut self, payload: &mut [u8]) -> InterceptVerdict {
        // TODO: One drawback with these rules is that they don't catch the first SYN packet of an inbound connection.
        let Ok(parsed) = SlicedPacket::from_ip(&payload) else {
            return InterceptVerdict::Accept;
        };

        let (src_ip, dst_ip, ip_header_size) = match &parsed.net {
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
        let verdict = self.transport_handler.on_transport_packet(src_ip, dst_ip, &mut payload[ip_header_size..]);

        let new_checksum = ipv4_checksum(
            &payload[ip_header_size..],
            payload[12..16].try_into().unwrap(),
            payload[16..20].try_into().unwrap(),
        );
        payload[ip_header_size + 16..ip_header_size + 18]
            .copy_from_slice(&new_checksum.to_be_bytes());

        return verdict;
    }
}

#[derive(Copy, Clone, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct TcpAddr<NetAddr: Copy + Hash + Ord + Default> {
    net: NetAddr,
    port: u16,
}

impl<NetAddr: Copy + Hash + Ord + Default> TcpAddr<NetAddr> {
    fn new(net: NetAddr, port: u16) -> Self {
        return TcpAddr{ net, port };
    }
}

struct TcpSessionMap<NetAddr: Copy + Hash + Ord + Default>(
    HashMap<(TcpAddr<NetAddr>, TcpAddr<NetAddr>), TcpSession<NetAddr>>,
);

impl<NetAddr: Copy + Hash + Ord + Default> TcpSessionMap<NetAddr> {
    fn get_session<'a>(
        &'a mut self,
        src_addr: TcpAddr<NetAddr>,
        dst_addr: TcpAddr<NetAddr>,
    ) -> &'a mut TcpSession<NetAddr> {
        // Sort them
        let key = if src_addr < dst_addr {
            (src_addr, dst_addr)
        } else {
            (dst_addr, src_addr)
        };

        self.0.entry(key).or_default()
    }
}

pub struct SnarfTcp<AH: ApplicationDataSnarfHandler, NetAddr>
where NetAddr: Copy + Hash + Ord + Default
{
    pub sessions: TcpSessionMap<NetAddr>,
    pub app_data_handler: AH,
}

impl<NetAddr: Copy + Hash + Ord + Default, AH: ApplicationDataSnarfHandler> TransportSnarfHandler<NetAddr> for SnarfTcp<AH, NetAddr>
{
    fn on_transport_packet(
        &mut self,
        src_net: NetAddr,
        dst_net: NetAddr,
        tcp_payload: &mut [u8],
    ) -> InterceptVerdict {
        let src_port = u16::from_be_bytes([tcp_payload[TCP_SRCPORT_OFFSET], tcp_payload[TCP_SRCPORT_OFFSET + 1]]);
        let dst_port = u16::from_be_bytes([tcp_payload[TCP_DSTPORT_OFFSET], tcp_payload[TCP_DSTPORT_OFFSET + 1]]);
        let header_len = (tcp_payload[TCP_DATAOFFSET_IDX] >> 4) as usize * 4;
        let payload_len = tcp_payload.len() - header_len;
        let data_payload = &tcp_payload[header_len..];

        if self.sessions.0.len() > 1000 {
            panic!("Too many sessions");
        }

        let src_addr = TcpAddr::new(src_net, src_port);
        let dst_addr = TcpAddr::new(dst_net, dst_port);
        let session = self.sessions.get_session(src_addr, dst_addr);

        let (is_client, buffered_payload, future) =
            session.read_tcp_packet(src_net, src_port, tcp_payload).unwrap();


        /*
         * If a packet comes from future, it should be issued only when the packet before it was
         * issued. The packets should be still separated.
         * */
        if future {
            return InterceptVerdict::Drop;
        }

        let data_payload = &mut tcp_payload[header_len..];
        if let Some(buffered_payload) = buffered_payload.as_ref() {
            data_payload.copy_from_slice(&buffered_payload);
        } else if payload_len > 0 {
            let verdict = self.app_data_handler.on_data(is_client, data_payload);
            session.add_sent_packet(src_net, src_port, tcp_payload);

            return verdict;
        }

        return InterceptVerdict::Accept;

        // We assume that if a retransmission happened, the host already received the initial packet
        /*
        if retransmission && !from_self {
            msg.set_verdict(nfq::Verdict::Drop);
            self.wait_for_verdict(running.clone(), msg).await.unwrap();
            continue;
        }
        */
    }
}

// type struct SnarfIpv4Tcp<AH: ApplicationDataSnarfHandler> = SnarfTcp<AH: ApplicationDataSnarfHandler, Ipv4Type>
pub type SnarfIpv4Tcp<AH> = SnarfTcp<AH, Ipv4Type>;

/*
pub struct Interceptor<TcpHandler>
where
    TcpHandler: TcpPacketInterceptorHandler
{
    queue: nfq::Queue,
    async_fd: AsyncFd<RawFd>,
    iface_ip: Vec<u8>,
    tcp_handler: TcpHandler,

    last_time_printed_stats: Instant,
    total_latency: Duration,
    msg_received: u64,
    latency_sec1: Duration,
    latency_sec2: Duration,
    latency_sec3: Duration,
    latency_sec4: Duration,
    cnt_sec3: u64,
}

impl<TcpHandler> Interceptor<TcpHandler>
where
    TcpHandler: TcpPacketInterceptorHandler
{
    fn new(opts: &InterceptorOptions, iface_ip: Vec<u8>, tcp_handler: TcpHandler) -> Result<Self, Box<dyn Error>> {
        let mut queue = nfq::Queue::open()?;
        queue.bind(opts.queue_num)?;
        queue.set_nonblocking(true);

        let async_fd = AsyncFd::new(queue.as_raw_fd())?;

        Ok(Self {
            queue,
            async_fd,
            iface_ip,
            tcp_handler,
            last_time_printed_stats: Instant::now(),
            total_latency: Duration::ZERO,
            msg_received: 0,
            latency_sec1: Duration::ZERO,
            latency_sec2: Duration::ZERO,
            latency_sec3: Duration::ZERO,
            latency_sec4: Duration::ZERO,
            cnt_sec3: 0,
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
                    panic!("Err: {err}");
                    return Err(err.into());
                }
            }
        }
    }

    fn get_next_msg_blocking(&mut self) -> Result<nfq::Message, Box<dyn Error>> {
        loop {
            match self.queue.recv() {
                Ok(msg) => {
                    return Ok(msg);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    panic!("queue would block");
                }
                Err(err) => {
                    return Err(err.into());
                }
            }
        }
    }

    async fn verdict(&mut self, msg: nfq::Message) -> Result<(), Box<dyn Error>> {
        let mut _guard = self.async_fd.writable().await?;

        match self.queue.verdict(msg) {
            Ok(msg) => Ok(msg),
            Err(err) => Err(err.into()),
        }
    }

    fn verdict_blocking(&mut self, msg: nfq::Message) -> Result<(), Box<dyn Error>> {
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

    async fn live_intercept(&mut self, running: Arc<AtomicBool>) -> Result<(), Box<dyn Error>> {
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

            let start_t = Instant::now();

            {
                let payload_len = msg.get_payload().len();
                let original_len = msg.get_original_len();
                if payload_len != original_len {
                    println!("len / original: {} / {}", payload_len, original_len);
                    panic!("Packet was truncated");
                }
            }

            let ip_payload = msg.get_payload_mut();

            let verdict: InterceptVerdict = self.on_packet(ip_payload);
            match verdict {
                InterceptVerdict::Accept => {
                    msg.set_verdict(nfq::Verdict::Accept);
                }
                InterceptVerdict::Drop => {
                    msg.set_verdict(nfq::Verdict::Drop);
                }
            }

            if Instant::now().duration_since(self.last_time_printed_stats) > Duration::from_secs(10) {
                let curr = Instant::now();
                self.last_time_printed_stats = curr;
                println!("total_latency: {:.1} ms", self.total_latency.as_millis());
                println!("msg_received: {:.1}", self.msg_received);
                println!("total_latency/msg: {:.4} us", (self.total_latency.as_micros() as f64) / (self.msg_received as f64));
                println!("latency_sec1/mgs: {:.4} us", (self.latency_sec1.as_micros() as f64) / (self.msg_received as f64));
                println!("latency_sec2/mgs: {:.4} us", (self.latency_sec2.as_micros() as f64) / (self.msg_received as f64));
                println!("latency_sec4/mgs: {:.4} us", (self.latency_sec4.as_micros() as f64) / (self.msg_received as f64));
            }

            self.msg_received += 1;
            let delta = Instant::now().duration_since(start_t);
            self.total_latency += delta;

            self.wait_for_verdict(running.clone(), msg).await.unwrap();
        }

        Ok(())
    }

    fn on_packet(&mut self, ip_payload: &mut [u8]) -> InterceptVerdict {
        // TODO: One drawback with these rules is that they don't catch the first SYN packet of an inbound connection.
        let Ok(parsed) = SlicedPacket::from_ip(&ip_payload) else {
            return InterceptVerdict::Accept;
        };

        let (src_ip, dst_ip, ip_header_size) = match &parsed.net {
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
        let verdict = self.on_tcp_packet(src_ip, dst_ip, &mut ip_payload[ip_header_size..]);

        let new_checksum = ipv4_checksum(
            &ip_payload[ip_header_size..],
            ip_payload[12..16].try_into().unwrap(),
            ip_payload[16..20].try_into().unwrap(),
        );
        ip_payload[ip_header_size + 16..ip_header_size + 18]
            .copy_from_slice(&new_checksum.to_be_bytes());

        return verdict;
    }

    /*
    fn on_tcp_packet<TcpHandler>(
        &mut self,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        tcp_payload: &mut [u8],
    )
    where
        TcpHandler: TcpPacketInterceptorHandler<T>
    {
        // TcpHandler::on_tcp_packet(self, src_ip, dst_ip, tcp_payload);
        self.tcp_handler.on_tcp_packet(self, src_ip, dst_ip, tcp_payload);
    }
    */
    fn on_tcp_packet(
        &mut self,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        tcp_payload: &mut [u8],
    ) -> InterceptVerdict
    {
        // TcpHandler::on_tcp_packet(self, src_ip, dst_ip, tcp_payload);
        self.tcp_handler.on_tcp_packet(self, src_ip, dst_ip, tcp_payload)
    }

    fn on_data(&mut self, is_client: bool, data: &mut [u8]) -> InterceptVerdict {
        InterceptVerdict::Accept
    }
}
*/

/*
pub async fn async_run_interceptor(
    opts: &InterceptorOptions,
    running: Arc<AtomicBool>,
    iface_ip: Vec<u8>,
    pcap_buffer: Producer<PcapPacket>,
) -> Result<(), Box<dyn Error>> {
    let mut interceptor = Interceptor::new(opts, iface_ip, pcap_buffer)?;

    interceptor.live_intercept(running).await
}

pub fn run_program(
    interceptor_opts: InterceptorOptions,
    dumper_opts: DumperOptions,
    running: Arc<AtomicBool>,
    iface_ip: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (producer, consumer) = RingBuffer::new(PCAP_BUFFER_SIZE);

    let running_clone = running.clone();
    let dumper_thread = rt.spawn_blocking(move || run_dumper(&dumper_opts, running_clone, consumer));
    /*
    let interceptor_task = rt.spawn(async move {
    });

    let local = tokio::task::LocalSet::new();
    let interceptor_task = rt.spawn(async move {
        local.run_until(async {
            tokio::task::spawn_local(async_run_interceptor(&interceptor_opts, running, iface_ip, producer)).await.unwrap();
        }).await;
    });
    */
    
    rt.block_on(async_run_interceptor(&interceptor_opts, running, iface_ip, producer))?;
    // rt.block_on(interceptor_task).unwrap();
    rt.block_on(dumper_thread).unwrap();

    Ok(())
}
*/
