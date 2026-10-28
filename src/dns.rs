//! A bounded DNS relay: clients use UDP or TCP, while every upstream query uses TCP.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const MAX_MESSAGE: usize = u16::MAX as usize;
const MAX_UDP: usize = 4096;
const WORKERS: usize = 32;
const QUEUE_SIZE: usize = 64;
const IO_TIMEOUT: Duration = Duration::from_secs(3);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_TCP_QUERIES: usize = 32;
const MAX_TCP_LIFETIME: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct Relay {
    upstreams: Vec<SocketAddr>,
    timeout: Duration,
}

struct Query {
    question_end: usize,
    udp_limit: usize,
}

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *data.get(offset)?,
        *data.get(offset + 1)?,
    ]))
}

// Return the first byte after the encoded name. Limit expansion and require
// compression pointers to point backwards, so loops and dangling pointers fail.
fn name_end(data: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    let mut end = None;
    let mut expanded = 1usize;
    loop {
        let len = *data.get(pos)?;
        if len & 0xc0 == 0xc0 {
            let target = (((len & 0x3f) as usize) << 8) | *data.get(pos + 1)? as usize;
            if target < 12 || target >= pos {
                return None;
            }
            end.get_or_insert(pos + 2);
            pos = target;
        } else if len & 0xc0 != 0 {
            return None;
        } else if len == 0 {
            return Some(end.unwrap_or(pos + 1));
        } else {
            expanded += len as usize + 1;
            if expanded > 255 || pos.checked_add(1 + len as usize)? > data.len() {
                return None;
            }
            pos += 1 + len as usize;
        }
    }
}

// Check the framing of every question and RR without interpreting RR data.
// This preserves unknown RR types and DNSSEC records byte-for-byte.
fn parse_message(data: &[u8], is_query: bool) -> Option<Query> {
    if data.len() < 12 || data.len() > MAX_MESSAGE {
        return None;
    }
    let flags = u16_at(data, 2)?;
    if (flags & 0x8000 == 0) != is_query {
        return None;
    }
    let questions = u16_at(data, 4)? as usize;
    if is_query && questions == 0 {
        return None;
    }
    let counts = [
        u16_at(data, 6)? as usize,
        u16_at(data, 8)? as usize,
        u16_at(data, 10)? as usize,
    ];
    let mut pos = 12;
    for _ in 0..questions {
        pos = name_end(data, pos)?.checked_add(4)?;
        if pos > data.len() {
            return None;
        }
    }
    let question_end = pos;
    let mut udp_limit = 512;
    let mut seen_opt = false;
    for (section, count) in counts.into_iter().enumerate() {
        for _ in 0..count {
            let name_start = pos;
            pos = name_end(data, pos)?;
            let kind = u16_at(data, pos)?;
            let class = u16_at(data, pos + 2)?;
            let rdlen = u16_at(data, pos + 8)? as usize;
            let end = pos.checked_add(10)?.checked_add(rdlen)?;
            if end > data.len() {
                return None;
            }
            if is_query && kind == 41 {
                // OPT is a single, root-owned pseudo-RR in the additional section.
                if section != 2 || seen_opt || data.get(name_start) != Some(&0) {
                    return None;
                }
                seen_opt = true;
                udp_limit = (class as usize).clamp(512, MAX_UDP);
                // OPT RDATA consists of length-delimited options.
                let mut option = pos + 10;
                while option < end {
                    let len = u16_at(data, option + 2)? as usize;
                    option = option.checked_add(4)?.checked_add(len)?;
                    if option > end {
                        return None;
                    }
                }
            }
            pos = end;
        }
    }
    if pos != data.len() {
        return None;
    }
    Some(Query {
        question_end,
        udp_limit,
    })
}

// Match the response question semantically, including compressed names and
// case-insensitive DNS labels. IDs alone are not sufficient validation.
fn question_key(data: &[u8]) -> Option<Vec<(Vec<u8>, u16, u16)>> {
    let mut pos = 12;
    let mut questions = Vec::new();
    for _ in 0..u16_at(data, 4)? {
        let next = name_end(data, pos)?;
        let mut cursor = pos;
        let mut name = Vec::new();
        loop {
            let len = *data.get(cursor)?;
            if len & 0xc0 == 0xc0 {
                cursor = (((len & 0x3f) as usize) << 8) | *data.get(cursor + 1)? as usize;
            } else if len == 0 {
                name.push(0);
                break;
            } else {
                name.push(len);
                let end = cursor.checked_add(1 + len as usize)?;
                name.extend(
                    data.get(cursor + 1..end)?
                        .iter()
                        .map(u8::to_ascii_lowercase),
                );
                cursor = end;
            }
        }
        questions.push((name, u16_at(data, next)?, u16_at(data, next + 2)?));
        pos = next + 4;
    }
    Some(questions)
}

fn matches_query(query: &[u8], response: &[u8]) -> bool {
    response.get(..2) == query.get(..2)
        && u16_at(query, 2)
            .zip(u16_at(response, 2))
            .is_some_and(|(q, r)| q & 0x7800 == r & 0x7800)
        && question_key(query)
            .zip(question_key(response))
            .is_some_and(|(q, r)| q == r)
}

// A whole frame has a deadline, not just each individual read/write. This
// prevents a peer from keeping a worker forever by sending one byte at a time.
fn read_exact_until(
    stream: &mut TcpStream,
    mut buf: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !buf.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "DNS read timeout"));
        }
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "DNS frame EOF",
                ));
            }
            Ok(n) => buf = &mut buf[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn read_frame(stream: &mut TcpStream, timeout: Duration) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut prefix = [0; 2];
    read_exact_until(stream, &mut prefix, deadline)?;
    let len = u16::from_be_bytes(prefix) as usize;
    if len < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short DNS frame",
        ));
    }
    let mut data = vec![0; len];
    read_exact_until(stream, &mut data, deadline)?;
    Ok(data)
}

fn write_frame(stream: &mut TcpStream, data: &[u8], timeout: Duration) -> io::Result<()> {
    let len = u16::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "oversized DNS frame"))?;
    let deadline = Instant::now() + timeout;
    let mut frame = Vec::with_capacity(data.len() + 2);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(data);
    let mut remaining_data = frame.as_slice();
    while !remaining_data.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "DNS write timeout"));
        }
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(remaining_data) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "DNS frame write")),
            Ok(n) => remaining_data = &remaining_data[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

impl Relay {
    fn exchange(&self, query: &[u8]) -> Option<Vec<u8>> {
        let mut last_servfail = None;
        for address in &self.upstreams {
            let result = (|| -> io::Result<Vec<u8>> {
                let mut stream = TcpStream::connect_timeout(address, self.timeout)?;
                write_frame(&mut stream, query, self.timeout)?;
                let response = read_frame(&mut stream, self.timeout)?;
                if parse_message(&response, false).is_none() || !matches_query(query, &response) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid DNS response",
                    ));
                }
                Ok(response)
            })();
            if let Ok(response) = result {
                // Retry another configured upstream for SERVFAIL, but not
                // for NXDOMAIN or other valid authoritative replies.
                if u16_at(&response, 2).is_some_and(|flags| flags & 0x000f == 2) {
                    last_servfail = Some(response);
                    continue;
                }
                return Some(response);
            }
        }
        last_servfail
    }
}

// Keep the original questions when they fit; a header-only truncated response
// is necessary if even the question section exceeds the UDP size limit.
fn synthetic(query: &[u8], parsed: &Query, flags: u16, limit: usize) -> Vec<u8> {
    let include_questions = parsed.question_end <= limit;
    let end = if include_questions {
        parsed.question_end
    } else {
        12
    };
    let mut response = query[..end].to_vec();
    let flags = if include_questions {
        flags
    } else {
        flags | 0x0200
    };
    response[2..4].copy_from_slice(&flags.to_be_bytes());
    if !include_questions {
        response[4..6].copy_from_slice(&0u16.to_be_bytes());
    }
    response[6..12].fill(0);
    response
}

fn servfail(query: &[u8], parsed: &Query, limit: usize) -> Vec<u8> {
    let query_flags = u16_at(query, 2).unwrap_or(0);
    // Preserve opcode, RD and CD. RA reflects availability of recursion.
    let flags = 0x8000 | 0x0080 | (query_flags & 0x7910) | 2;
    synthetic(query, parsed, flags, limit)
}

fn answer(relay: &Relay, query: &[u8], parsed: &Query, udp: bool) -> Vec<u8> {
    let limit = if udp { parsed.udp_limit } else { MAX_MESSAGE };
    match relay.exchange(query) {
        Some(response) if response.len() > limit => {
            let flags = u16_at(&response, 2).unwrap_or(0) | 0x8200;
            synthetic(query, parsed, flags, limit)
        }
        Some(response) => response,
        None => servfail(query, parsed, limit),
    }
}

fn handle_tcp(mut stream: TcpStream, relay: &Relay) {
    let deadline = Instant::now() + MAX_TCP_LIFETIME;
    for _ in 0..MAX_TCP_QUERIES {
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .min(CLIENT_TIMEOUT);
        if timeout.is_zero() {
            break;
        }
        let Ok(query) = read_frame(&mut stream, timeout) else {
            break;
        };
        let Some(parsed) = parse_message(&query, true) else {
            break;
        };
        let response = answer(relay, &query, &parsed, false);
        if write_frame(&mut stream, &response, CLIENT_TIMEOUT).is_err() {
            break;
        }
    }
}

fn handle_udp(socket: &UdpSocket, peer: SocketAddr, query: &[u8], relay: &Relay) {
    if let Some(parsed) = parse_message(query, true) {
        let response = answer(relay, query, &parsed, true);
        let _ = socket.send_to(&response, peer);
    }
}

enum Job {
    Tcp(TcpStream),
    Udp(Vec<u8>, SocketAddr),
}

/// Bind loopback UDP and TCP port 53, then notify the caller and run the relay.
/// Each upstream attempt is a fresh, directly routed TCP connection to port 53.
pub fn serve(
    upstreams: Vec<Ipv4Addr>,
    ready: impl FnOnce() -> io::Result<()> + Send + 'static,
) -> anyhow::Result<()> {
    let udp = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 53))?);
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 53))?;
    udp.set_read_timeout(Some(Duration::from_millis(100)))?;
    tcp.set_nonblocking(true)?;
    let relay = Arc::new(Relay {
        upstreams: upstreams
            .into_iter()
            .map(|ip| SocketAddr::from((ip, 53)))
            .collect(),
        timeout: IO_TIMEOUT,
    });
    let (sender, receiver) = mpsc::sync_channel::<Job>(QUEUE_SIZE);
    let receiver = Arc::new(Mutex::new(receiver));
    for index in 0..WORKERS {
        let receiver = Arc::clone(&receiver);
        let relay = Arc::clone(&relay);
        let udp = Arc::clone(&udp);
        thread::Builder::new()
            .name(format!("dns-{index}"))
            .spawn(move || {
                loop {
                    let job = match receiver.lock() {
                        Ok(receiver) => receiver.recv(),
                        Err(_) => break,
                    };
                    match job {
                        Ok(Job::Tcp(stream)) => handle_tcp(stream, &relay),
                        Ok(Job::Udp(query, peer)) => handle_udp(&udp, peer, &query, &relay),
                        Err(_) => break,
                    }
                }
            })?;
    }
    ready()?;
    let mut buf = [0; MAX_MESSAGE + 1];
    loop {
        // Bound accepts per iteration so a TCP flood cannot starve UDP.
        for _ in 0..WORKERS {
            match tcp.accept() {
                Ok((stream, _)) => {
                    // Dropping a connection on overload bounds both memory and threads.
                    let _ = sender.try_send(Job::Tcp(stream));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        match udp.recv_from(&mut buf) {
            Ok((size, peer)) if size <= MAX_MESSAGE => {
                let query = buf[..size].to_vec();
                if let Err(mpsc::TrySendError::Full(Job::Udp(query, peer))) =
                    sender.try_send(Job::Udp(query, peer))
                    && let Some(parsed) = parse_message(&query, true)
                {
                    let _ = udp.send_to(&servfail(&query, &parsed, parsed.udp_limit), peer);
                }
            }
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(id: u16, qtype: u16, edns: Option<u16>) -> Vec<u8> {
        let mut data = vec![0; 12];
        data[..2].copy_from_slice(&id.to_be_bytes());
        data[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
        data[4..6].copy_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(b"\x07example\x03com\0");
        data.extend_from_slice(&qtype.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        if let Some(size) = edns {
            data[10..12].copy_from_slice(&1u16.to_be_bytes());
            data.extend_from_slice(&[0, 0, 41]);
            data.extend_from_slice(&size.to_be_bytes());
            data.extend_from_slice(&[0, 0, 0x80, 0, 0, 0]);
        }
        data
    }

    fn response(query: &[u8], rcode: u8, payload_len: usize) -> Vec<u8> {
        let parsed = parse_message(query, true).unwrap();
        let mut data = query[..parsed.question_end].to_vec();
        data[2..4].copy_from_slice(&(0x8180u16 | u16::from(rcode)).to_be_bytes());
        data[6..12].fill(0);
        if payload_len > 0 {
            data[6..8].copy_from_slice(&1u16.to_be_bytes());
            data.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 1]);
            data.extend_from_slice(&(payload_len as u16).to_be_bytes());
            data.extend(vec![0x5a; payload_len]);
        }
        data
    }

    fn listener() -> TcpListener {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap()
    }

    fn relay(addresses: Vec<SocketAddr>) -> Relay {
        Relay {
            upstreams: addresses,
            timeout: Duration::from_millis(150),
        }
    }

    // The test server deliberately accepts a fresh connection for each query.
    fn upstream(
        count: usize,
        rcode: u8,
        payload: usize,
        fragmented: bool,
    ) -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = listener();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            for _ in 0..count {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_frame(&mut stream, Duration::from_secs(2)).unwrap();
                let reply = response(&request, rcode, payload);
                if fragmented {
                    let mut frame = (reply.len() as u16).to_be_bytes().to_vec();
                    frame.extend_from_slice(&reply);
                    for chunk in frame.chunks(1) {
                        stream.write_all(chunk).unwrap();
                        thread::sleep(Duration::from_millis(1));
                    }
                } else {
                    write_frame(&mut stream, &reply, Duration::from_secs(2)).unwrap();
                }
            }
        });
        (address, handle)
    }

    #[test]
    fn tcp_pipeline_and_fragmented_frames() {
        let (upstream, upstream_thread) = upstream(2, 0, 0, true);
        let server = listener();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = server.accept().unwrap();
            handle_tcp(stream, &relay(vec![upstream]));
        });
        let mut client = TcpStream::connect(address).unwrap();
        let first = query(0x1234, 1, None);
        let second = query(0x5678, 28, None);
        let mut wire = Vec::new();
        for request in [&first, &second] {
            wire.extend_from_slice(&(request.len() as u16).to_be_bytes());
            wire.extend_from_slice(request);
        }
        // Fragment the prefix and payload while sending both requests before reading.
        for chunk in wire.chunks(1) {
            client.write_all(chunk).unwrap();
        }
        assert_eq!(
            read_frame(&mut client, Duration::from_secs(2)).unwrap(),
            response(&first, 0, 0)
        );
        assert_eq!(
            read_frame(&mut client, Duration::from_secs(2)).unwrap(),
            response(&second, 0, 0)
        );
        drop(client);
        worker.join().unwrap();
        upstream_thread.join().unwrap();
    }

    fn udp_roundtrip(request: &[u8], relay: Relay) -> Vec<u8> {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .send_to(request, server.local_addr().unwrap())
            .unwrap();
        let mut buf = [0; MAX_MESSAGE];
        let (size, peer) = server.recv_from(&mut buf).unwrap();
        handle_udp(&server, peer, &buf[..size], &relay);
        let (size, _) = client.recv_from(&mut buf).unwrap();
        buf[..size].to_vec()
    }

    #[test]
    fn udp_uses_tcp_upstream_and_preserves_wire() {
        let (upstream, thread) = upstream(1, 0, 20, false);
        let request = query(9, 28, Some(1232));
        assert_eq!(
            udp_roundtrip(&request, relay(vec![upstream])),
            response(&request, 0, 20)
        );
        thread.join().unwrap();
    }

    #[test]
    fn udp_edns_limit_and_default_truncate() {
        for (edns, payload, truncated) in [
            (None, 600, true),
            (Some(512), 600, true),
            (Some(1232), 600, false),
            (Some(6000), 4100, true),
        ] {
            let (upstream, thread) = upstream(1, 0, payload, false);
            let request = query(0xaabb, 1, edns);
            let result = udp_roundtrip(&request, relay(vec![upstream]));
            assert_eq!(u16_at(&result, 2).unwrap() & 0x0200 != 0, truncated);
            assert_eq!(&result[..2], &request[..2]);
            if truncated {
                let parsed = parse_message(&request, true).unwrap();
                assert_eq!(&result[12..], &request[12..parsed.question_end]);
                assert!(parse_message(&result, false).is_some());
                assert!(result.len() <= parsed.udp_limit);
            } else {
                assert_eq!(result, response(&request, 0, payload));
            }
            thread.join().unwrap();
        }
    }

    #[test]
    fn nxdomain_does_not_fallback() {
        let rcode = 3;
        let (upstream, thread) = upstream(1, rcode, 0, false);
        let unused = listener();
        unused.set_nonblocking(true).unwrap();
        let request = query(5, 1, None);
        let result = relay(vec![upstream, unused.local_addr().unwrap()])
            .exchange(&request)
            .unwrap();
        assert_eq!(result, response(&request, rcode, 0));
        assert_eq!(
            unused.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        thread.join().unwrap();
    }

    #[test]
    fn servfail_uses_next_configured_upstream() {
        let (failed, failed_thread) = upstream(1, 2, 0, false);
        let (good, good_thread) = upstream(1, 0, 0, false);
        let request = query(5, 1, None);
        let result = relay(vec![failed, good]).exchange(&request).unwrap();
        assert_eq!(result, response(&request, 0, 0));
        failed_thread.join().unwrap();
        good_thread.join().unwrap();
    }

    #[test]
    fn bad_id_and_timeout_fallback_and_exhaustion_servfail() {
        let bad = listener();
        let bad_address = bad.local_addr().unwrap();
        let bad_thread = thread::spawn(move || {
            let (mut stream, _) = bad.accept().unwrap();
            let request = read_frame(&mut stream, Duration::from_secs(2)).unwrap();
            let mut reply = response(&request, 0, 0);
            reply[1] ^= 1;
            write_frame(&mut stream, &reply, Duration::from_secs(2)).unwrap();
        });
        let slow = listener();
        let slow_address = slow.local_addr().unwrap();
        let slow_thread = thread::spawn(move || {
            let (mut stream, _) = slow.accept().unwrap();
            let _ = read_frame(&mut stream, Duration::from_secs(2)).unwrap();
            thread::sleep(Duration::from_millis(300));
        });
        let (good, good_thread) = upstream(1, 0, 0, false);
        let request = query(0x8888, 1, None);
        let result = relay(vec![bad_address, slow_address, good])
            .exchange(&request)
            .unwrap();
        assert_eq!(result, response(&request, 0, 0));
        bad_thread.join().unwrap();
        slow_thread.join().unwrap();
        good_thread.join().unwrap();
        let failed = udp_roundtrip(&request, relay(vec![]));
        assert_eq!(&failed[..2], &request[..2]);
        assert_eq!(u16_at(&failed, 2).unwrap() & 15, 2);
        assert!(parse_message(&failed, false).is_some());
    }

    #[test]
    fn response_question_must_match_even_when_id_matches() {
        let request = query(123, 1, None);
        let mut wrong_name = response(&request, 0, 0);
        wrong_name[13] = b'z';
        assert!(!matches_query(&request, &wrong_name));
        let mut wrong_type = response(&request, 0, 0);
        let end = parse_message(&request, true).unwrap().question_end;
        wrong_type[end - 3] = 28;
        assert!(!matches_query(&request, &wrong_type));
        let mut changed_case = response(&request, 0, 0);
        changed_case[13] = b'E';
        assert!(matches_query(&request, &changed_case));
    }

    #[test]
    fn rejects_bad_messages_and_compression_loops() {
        let mut request = query(1, 1, None);
        request[12] = 0xc0;
        request[13] = 12;
        assert!(parse_message(&request, true).is_none());
        let mut request = query(1, 1, Some(1232));
        request.pop();
        assert!(parse_message(&request, true).is_none());
        let mut request = query(1, 1, None);
        request[2] |= 0x80;
        assert!(parse_message(&request, true).is_none());
    }
}
