use std::hash::Hash;
use std::time::Instant;

use crate::TransportPacketParent;
use crate::tcp_tracker::{
    FutureVerdict,
    TcpPeerTracker,
    TcpTrackerPlungeResult,
    TcpTrackerRiseResult,
};
use crate::tcp_util::{
    TCP_FLAGS_IDX,
    tcp_header_len,
    tcp_seq,
};

#[derive(Debug, Clone)]
pub enum SnarfTcpError {
    PacketTooBigError,
}
use SnarfTcpError::*;

type Result<T> = std::result::Result<T, SnarfTcpError>;

// A struct that should be only created by TcpPeerTracker::plunge
#[derive(Clone, Debug)]
struct WindInput {
    is_client: bool,
    tracker_wind_input: TrackerWindInput,
}

impl WindInput {
    fn new(is_client: bool, tracker_wind_input: TrackerWindInput) -> Self {
        Self {
            is_client,
            tracker_wind_input,
        }
    }
}

pub struct PlungeResult {
    is_client: bool,
    tracker_plunge_result: TcpTrackerPlungeResult,
}

impl PlungeResult {
    fn new(is_client: bool, tracker_plunge_result: TcpTrackerPlungeResult) -> Self {
        Self {
            is_client,
            tracker_plunge_result,
        }
    }

    pub fn tracker_result(&self) -> &TcpTrackerPlungeResult {
        &self.tracker_plunge_result
    }
}

// A struct that should be only created by TcpPeerTracker::plunge
#[derive(Clone, Debug)]
pub struct RewindInput {
    is_client: bool,
    tracker_rewind_input: TrackerRewindInput,
}

impl RewindInput {
    fn from_tracker(is_client: bool, tracker_input: Option<TcpTrackerRewindInput>) -> Option<Self> {
        tracker_input.map(|x| {
            Self {
                is_client,
                tracker_rewind_input: x,
            }
        })
    }
}

// A struct that should be only created by TcpPeerTracker::plunge
#[derive(Clone, Debug)]
pub struct RiseInput {
    is_client: bool,
    tracker_rise_input: TcpTrackerRiseInput,
}

impl RiseInput {
    fn from_tracker(is_client: bool, tracker_input: Option<TcpTrackerRiseInput>) -> Option<Self> {
        tracker_input.map(|x| {
            Self {
                is_client,
                tracker_rise_input: x,
            }
        })
    }
}

// (is_client, TcpParsePlungeResult)
pub type TcpPlungeResult<'a> = (
    bool,
    TcpTrackerPlungeResult,
);

#[derive(Debug)]
pub struct TcpSession<NetAddr, RF>
where
    NetAddr: Copy + Hash + Ord,
    RF: TransportPacketParent,
{
    pub src_net: NetAddr,
    pub src_port: u16,
    pub src_tracker: TcpPeerTracker<RF>,
    pub dst_tracker: TcpPeerTracker<RF>,
    pub src_init: bool,
    pub handshake_done: bool,
    pub created: Instant,
}

impl<NetAddr, RF> Default for TcpSession<NetAddr, RF>
where
    NetAddr: Copy + Hash + Ord + Default,
    RF: TransportPacketParent,
{
    fn default() -> Self {
        Self {
            src_net: NetAddr::default(),
            src_port: 0,
            src_tracker: TcpPeerTracker::new(),
            dst_tracker: TcpPeerTracker::new(),
            src_init: false,
            handshake_done: false,
            created: Instant::now(),
        }
    }
}

impl<NetAddr, RF> TcpSession<NetAddr, RF>
where
    NetAddr: Copy + Hash + Ord,
    RF: TransportPacketParent,
{
    pub fn rise_tcp_packet<'a>(
        &'a mut self,
        is_client: bool,
        rise_input: RiseInput,
    ) -> Result<TcpTrackerRiseResult<'a>> {
        if is_client {
            self.src_tracker.rise(rise_input)
        } else {
            self.dst_tracker.rise(rise_input)
        }
    }

    pub fn plunge_tcp_packet<'a>(
        &self,
        src_net: NetAddr,
        src_port: u16,
        tcp_payload: &mut [u8],
    ) -> Result<WindInput> {
        if !self.src_init {
            self.src_net = src_net;
            self.src_port = src_port;
            self.src_init = true;
        }

        let seq = tcp_seq(tcp_payload);
        let flags = tcp_payload[TCP_FLAGS_IDX];
        let header_len = tcp_header_len(tcp_payload);
        let data = &mut tcp_payload[header_len..];

        if self.src_net == src_net && self.src_port == src_port {
            let is_client = true;
            let tracker_wind_input = self.src_tracker.plunge(flags, seq, data)?;

            Ok(WindInput::new(is_client, tracker_wind_input))
        } else {
            let is_client = false;
            let tracker_wind_input = self.dst_tracker.plunge(flags, seq, data)?;

            Ok(WindInput::new(is_client, tracker_wind_input))
        }
    }

    pub fn wind(&mut self, input: WindInput) -> Result<(Option<RiseInput>, RewindInput)> {
        let rise_input;
        let rewind_input;
        if input.is_client {
            (rise_input, rewind_input) = self.src_tracker.wind(input.tracker_wind_input)?;
        } else {
            (rise_input, rewind_input) = self.dst_tracker.wind(input.tracker_wind_input)?;
        }

        Ok((RiseInput::from_tracker(is_client, rise_input), RewindInput::from_tracker(is_client, rewind_input)))
    }

    pub fn add_future_payload(
        &mut self,
        is_client: bool,
        parent_reference: RF,
    ) -> std::result::Result<(), (RF, SnarfTcpError)> {
        if is_client {
            self.src_tracker.add_future_payload(parent_reference)
        } else {
            self.dst_tracker.add_future_payload(parent_reference)
        }
    }

    pub fn verdict_kept<'a>(&'a mut self, is_client: bool) -> Vec<FutureVerdict<'a, RF>> {
        if is_client {
            self.src_tracker.update_future_queue()
        } else {
            self.dst_tracker.update_future_queue()
        }
    }

    pub fn drain_nowrite_future_queue(
        &mut self,
        is_client: bool,
    ) -> Vec<FutureVerdict<'static, RF>> {
        if is_client {
            self.src_tracker.drain_nowrite_future_queue()
        } else {
            self.dst_tracker.drain_nowrite_future_queue()
        }
    }
}
