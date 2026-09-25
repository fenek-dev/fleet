use super::*;
use crate::runner::FakeRunner;
use crate::testutil::{block, ctx, meta};
use fleet_proto::args::{Endpoint, Port, WgKey};

const PRIV: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const PUB: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";
const PEER: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

fn cidr(s: &str) -> Cidr {
    s.parse().unwrap()
}

fn peer(key: &str, ip: &str, endpoint: Option<&str>) -> WgPeer {
    WgPeer {
        public_key: WgKey::new(key_from_b64(key).unwrap()).unwrap(),
        endpoint: endpoint.map(|e| {
            let sa: SocketAddr = e.parse().unwrap();
            Endpoint {
                addr: sa.ip(),
                port: Port::new(sa.port()).unwrap(),
            }
        }),
        allowed_ips: vec![cidr(ip)],
        keepalive_s: 25,
    }
}

fn config() -> MeshConfig {
    MeshConfig {
        address: "10.77.0.1".parse().unwrap(),
        network: cidr("10.77.0.0/24"),
        listen_port: Port::new(51820).unwrap(),
        peers: vec![
            peer(PEER, "10.77.0.2/32", Some("203.0.113.2:51820")),
            peer(PUB, "10.77.0.3/32", Some("[2001:db8::3]:51820")),
        ],
    }
}

const GOLDEN: &str = "# Managed by Fleet (mesh.join). Changes are overwritten.
[Interface]
Address = 10.77.0.1/24
ListenPort = 51820
PostUp = /usr/bin/wg set %i private-key /etc/wireguard/fleet0.key

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 10.77.0.2/32
Endpoint = 203.0.113.2:51820
PersistentKeepalive = 25

[Peer]
PublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=
AllowedIPs = 10.77.0.3/32
Endpoint = [2001:db8::3]:51820
PersistentKeepalive = 25
";

#[test]
fn base64_keys() {
    for k in [PRIV, PUB, PEER] {
        assert_eq!(b64_encode(&key_from_b64(k).unwrap()), k);
    }
    assert_eq!(b64_encode(&[0u8; 32]), format!("{}=", "A".repeat(43)));
    assert_eq!(b64_encode(b"fo"), "Zm8=");
    assert_eq!(b64_encode(b"foo"), "Zm9v");
    assert!(key_from_b64("short=").is_none());
    assert!(key_from_b64(&PUB.replace('=', "A")).is_none());
    // Non-canonical trailing bits.
    assert!(key_from_b64("HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykx=").is_none());
    assert!(key_from_b64("!Igo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=").is_none());
}

#[test]
fn conf_golden_and_parse_back() {
    let c = render_conf(&config());
    assert_eq!(c, GOLDEN);
    let i = parse_iface(&c).unwrap();
    assert_eq!(i.address, "10.77.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(i.network, cidr("10.77.0.0/24"));
    assert_eq!(i.listen_port, 51820);
    assert!(iface_part(&c).ends_with("private-key /etc/wireguard/fleet0.key"));
    assert!(!iface_part(&c).contains("[Peer]"));
}

#[test]
fn dump_parsing_drops_private_key() {
    let dump = format!(
        "{PRIV}\t{PUB}\t51820\toff\n\
         {PEER}\t(none)\t203.0.113.2:51820\t10.77.0.2/32\t1700000000\t1234\t5678\t25\n\
         {PUB}\t(none)\t(none)\t(none)\t0\t0\t0\toff\n\
         garbage line\n"
    );
    let peers = parse_dump(&dump);
    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0].public_key, key_from_b64(PEER).unwrap());
    assert_eq!(
        peers[0].endpoint,
        Some("203.0.113.2:51820".parse().unwrap())
    );
    assert_eq!(peers[0].allowed_ips, vec!["10.77.0.2/32".to_owned()]);
    assert_eq!(peers[0].last_handshake_ms, Some(1_700_000_000_000));
    assert_eq!((peers[0].rx_bytes, peers[0].tx_bytes), (1234, 5678));
    assert_eq!(peers[1].endpoint, None);
    assert!(peers[1].allowed_ips.is_empty());
    assert_eq!(peers[1].last_handshake_ms, None);
    let dbg = format!("{peers:?}");
    assert!(!dbg.contains(PRIV));
}

fn root() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("etc")).unwrap();
    d
}

fn read(d: &tempfile::TempDir, p: &str) -> String {
    std::fs::read_to_string(d.path().join(p.trim_start_matches('/'))).unwrap()
}

fn mode(d: &tempfile::TempDir, p: &str) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(d.path().join(p.trim_start_matches('/')))
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn join_generates_key_writes_conf_and_starts() {
    let d = root();
    let r = Rc::new(FakeRunner::new());
    r.expect(WG, &["genkey"], Ok(CommandOutput::ok(format!("{PRIV}\n"))))
        .expect(WG, &["pubkey"], Ok(CommandOutput::ok(format!("{PUB}\n"))))
        .expect(
            SYSTEMCTL,
            &["is-active", "--quiet", UNIT],
            Ok(CommandOutput::exit(3)),
        )
        .expect(
            SYSTEMCTL,
            &["enable", "--now", UNIT],
            Ok(CommandOutput::ok("")),
        );
    let c = ctx(d.path(), r.clone());
    let op = Op::MeshJoin(config());
    MeshHandler
        .validate(&c, &op, &meta(op.clone(), None))
        .unwrap();
    let out = block(MeshHandler.handle(&c, &op, &meta(op.clone(), Some(3)))).unwrap();
    let OpOutput::Payload(Payload::ChangePending { change: p, .. }) = out else {
        panic!()
    };
    assert_eq!(p.new_version, Some(fswrite::version_of(GOLDEN.as_bytes())));
    assert_eq!(r.pending(), 0);
    // `wg pubkey` got the private key on stdin, nothing else did.
    let calls = r.calls();
    assert_eq!(
        calls[1].stdin.as_deref(),
        Some(format!("{PRIV}\n").as_bytes())
    );
    assert!(
        calls
            .iter()
            .all(|c| !c.args.iter().any(|a| a.to_string_lossy().contains(PRIV)))
    );
    assert_eq!(read(&d, KEY), format!("{PRIV}\n"));
    assert_eq!(read(&d, CONF), GOLDEN);
    assert_eq!(
        (mode(&d, KEY), mode(&d, CONF), mode(&d, DIR)),
        (0o600, 0o600, 0o700)
    );

    // Re-join: key reused, service restarted.
    let r2 = Rc::new(FakeRunner::new());
    r2.expect(WG, &["pubkey"], Ok(CommandOutput::ok(PUB)))
        .expect(
            SYSTEMCTL,
            &["is-active", "--quiet", UNIT],
            Ok(CommandOutput::ok("")),
        )
        .expect(SYSTEMCTL, &["restart", UNIT], Ok(CommandOutput::ok("")));
    let c2 = ctx(d.path(), r2.clone());
    block(MeshHandler.handle(&c2, &op, &meta(op.clone(), Some(4)))).unwrap();
    assert_eq!(r2.pending(), 0);
}

#[test]
fn peers_set_is_versioned_and_reloads() {
    let d = root();
    std::fs::create_dir_all(d.path().join("etc/wireguard")).unwrap();
    std::fs::write(d.path().join("etc/wireguard/fleet0.conf"), GOLDEN).unwrap();
    let r = Rc::new(FakeRunner::new());
    let c = ctx(d.path(), r.clone());
    let peers = vec![peer(PEER, "10.77.0.9/32", None)];
    let op = Op::MeshPeersSet {
        peers: peers.clone(),
    };
    let mut m = meta(op.clone(), None);
    let current = fswrite::version_of(GOLDEN.as_bytes());
    m.command.body.expected_version = Some(current ^ 1);
    assert_eq!(
        MeshHandler.validate(&c, &op, &m).unwrap_err().code(),
        ErrorCode::VersionConflict { current }
    );
    m.command.body.expected_version = Some(current);
    MeshHandler.validate(&c, &op, &m).unwrap();
    // Outside the mesh network: refused.
    let bad = Op::MeshPeersSet {
        peers: vec![peer(PEER, "10.78.0.9/32", None)],
    };
    let mut mb = meta(bad.clone(), None);
    mb.command.body.expected_version = Some(current);
    assert_eq!(
        MeshHandler.validate(&c, &bad, &mb).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );

    r.expect(SYSTEMCTL, &["reload", UNIT], Ok(CommandOutput::ok("")));
    m.audit_seq = Some(5);
    block(MeshHandler.handle(&c, &op, &m)).unwrap();
    let conf = read(&d, CONF);
    assert!(conf.starts_with(iface_part(GOLDEN)));
    assert!(conf.contains("AllowedIPs = 10.77.0.9/32\nPersistentKeepalive = 25\n"));
    assert_eq!(conf.matches("[Peer]").count(), 1);

    // Not joined → NotFound.
    std::fs::remove_file(d.path().join("etc/wireguard/fleet0.conf")).unwrap();
    assert_eq!(
        MeshHandler.validate(&c, &op, &m).unwrap_err().code(),
        ErrorCode::NotFound
    );
}

#[test]
fn status_reports_public_key_and_peers() {
    let d = root();
    std::fs::create_dir_all(d.path().join("etc/wireguard")).unwrap();
    std::fs::write(d.path().join("etc/wireguard/fleet0.conf"), GOLDEN).unwrap();
    std::fs::write(d.path().join("etc/wireguard/fleet0.key"), PRIV).unwrap();
    let dump = format!(
        "{PRIV}\t{PUB}\t51820\toff\n{PEER}\t(none)\t203.0.113.2:51820\t10.77.0.2/32\t0\t1\t2\toff\n"
    );
    let r = Rc::new(FakeRunner::new());
    r.expect(WG, &["pubkey"], Ok(CommandOutput::ok(PUB)))
        .expect(WG, &["show", "fleet0", "dump"], Ok(CommandOutput::ok(dump)));
    let c = ctx(d.path(), r.clone());
    let op = Op::MeshStatus;
    let out = block(MeshHandler.handle(&c, &op, &meta(op.clone(), Some(1)))).unwrap();
    let OpOutput::Payload(Payload::MeshStatus(s)) = out else {
        panic!()
    };
    assert!(s.joined);
    assert_eq!(s.public_key, key_from_b64(PUB));
    assert_eq!(s.listen_port, Some(51820));
    assert_eq!(s.peers.len(), 1);

    // Not joined: no conf, no key.
    let d2 = root();
    let c2 = ctx(d2.path(), Rc::new(FakeRunner::new()));
    let out = block(MeshHandler.handle(&c2, &op, &meta(op.clone(), Some(2)))).unwrap();
    let OpOutput::Payload(Payload::MeshStatus(s)) = out else {
        panic!()
    };
    assert!(!s.joined && s.public_key.is_none() && s.peers.is_empty());
}

#[test]
fn leave_and_revert() {
    let d = root();
    std::fs::create_dir_all(d.path().join("etc/wireguard")).unwrap();
    std::fs::write(d.path().join("etc/wireguard/fleet0.conf"), GOLDEN).unwrap();
    std::fs::write(d.path().join("etc/wireguard/fleet0.key"), PRIV).unwrap();
    let r = Rc::new(FakeRunner::new());
    r.expect(
        SYSTEMCTL,
        &["is-active", "--quiet", UNIT],
        Ok(CommandOutput::ok("")),
    )
    .expect(
        SYSTEMCTL,
        &["is-enabled", "--quiet", UNIT],
        Ok(CommandOutput::ok("")),
    )
    .expect(
        SYSTEMCTL,
        &["disable", "--now", UNIT],
        Ok(CommandOutput::ok("")),
    )
    .expect(SYSTEMCTL, &["restart", UNIT], Ok(CommandOutput::ok("")))
    .expect(SYSTEMCTL, &["enable", UNIT], Ok(CommandOutput::ok("")));
    let c = ctx(d.path(), r.clone());
    let op = Op::MeshLeave;
    let snap = MeshRevert.snapshot(&c, &op).unwrap();
    let s: MeshSnapshot = fleet_proto::decode(&snap).unwrap();
    assert!(s.active && s.enabled && s.key_present);
    assert!(
        !String::from_utf8_lossy(&snap).contains(PRIV),
        "no secret in the snapshot"
    );
    block(MeshHandler.handle(&c, &op, &meta(op.clone(), Some(1)))).unwrap();
    assert!(!d.path().join("etc/wireguard/fleet0.conf").exists());
    assert!(
        d.path().join("etc/wireguard/fleet0.key").exists(),
        "key kept"
    );
    MeshRevert.restore(&c, &snap).unwrap();
    assert_eq!(read(&d, CONF), GOLDEN);
    assert_eq!(r.pending(), 0);

    // Reverting a first join: conf and the new key go, service off.
    let first = fleet_proto::encode(&MeshSnapshot {
        conf: None,
        key_present: false,
        active: false,
        enabled: false,
    });
    let r2 = Rc::new(FakeRunner::new());
    r2.expect(SYSTEMCTL, &["stop", UNIT], Ok(CommandOutput::ok("")))
        .expect(SYSTEMCTL, &["disable", UNIT], Ok(CommandOutput::ok("")));
    let c2 = ctx(d.path(), r2.clone());
    MeshRevert.restore(&c2, &first).unwrap();
    assert!(!d.path().join("etc/wireguard/fleet0.conf").exists());
    assert!(!d.path().join("etc/wireguard/fleet0.key").exists());
    // Idempotent.
    r2.expect(SYSTEMCTL, &["stop", UNIT], Ok(CommandOutput::ok("")))
        .expect(SYSTEMCTL, &["disable", UNIT], Ok(CommandOutput::ok("")));
    MeshRevert.restore(&c2, &first).unwrap();
    assert_eq!(r2.pending(), 0);
}
