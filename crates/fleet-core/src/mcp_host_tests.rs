//! Socket protocol tests, in process: frames through `handle_frame` and
//! `serve` over an in-memory duplex, with fake executor, approver and UI.

use super::*;
use crate::bulk::tests::{Behave, FakeExec, SoftApprover, healthy, sid};
use fleet_proto::payload::ConfigPaths;
use std::collections::HashSet;
use tokio::sync::mpsc;

struct Backend {
    exec: Arc<FakeExec>,
    approver: Arc<SoftApprover>,
    locked: AtomicBool,
    running: AtomicBool,
    paired: Mutex<HashSet<String>>,
    n: usize,
    /// Pushed-policy AI limits (every server).
    limits: Mutex<Option<AiLimits>>,
    /// Pushed-policy AI limits of single servers (over `limits`).
    server_limits: Mutex<HashMap<ServerId, AiLimits>>,
    confirmed: Mutex<Vec<(ServerId, fleet_proto::ChangeId, Actor)>>,
    saved: Mutex<Vec<McpClientRecord>>,
}

impl McpBackend for Backend {
    fn executor(&self) -> Result<Arc<dyn BulkExecutor>, ProtoError> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(ProtoError::NotRunning);
        }
        Ok(Arc::new(self.exec.clone()))
    }
    fn approver(&self) -> Option<Arc<dyn Approver>> {
        Some(self.approver.clone())
    }
    fn locked(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }
    fn servers(&self) -> Vec<ServerSummary> {
        (0..self.n)
            .map(|i| ServerSummary {
                id: sid(i),
                name: format!("web-{i}"),
                group: None,
                tags: if i % 2 == 0 {
                    vec!["even".into()]
                } else {
                    vec![]
                },
                state: "Ready".into(),
            })
            .collect()
    }
    fn paired(&self, key: &str) -> bool {
        lock(&self.paired).contains(key)
    }
    fn save_pairing(&self, rec: McpClientRecord) -> Result<(), ProtoError> {
        lock(&self.paired).insert(rec.key.clone());
        lock(&self.saved).push(rec);
        Ok(())
    }
    fn ai_limits(&self, server: &ServerId) -> Option<AiLimits> {
        lock(&self.server_limits)
            .get(server)
            .copied()
            .or(*lock(&self.limits))
    }
    fn confirm_change(
        &self,
        server: ServerId,
        change: PendingChange,
        actor: Actor,
    ) -> BoxFut<Result<(), ConfirmFailure>> {
        lock(&self.confirmed).push((server, change.change_id, actor));
        Box::pin(async { Ok(()) })
    }
}

/// Answers prompts with `answer` (None: never answers).
struct Ui {
    tx: mpsc::UnboundedSender<Prompt>,
}
impl McpUi for Ui {
    fn show_prompt(&self, prompt: Prompt) {
        let _ = self.tx.send(prompt);
    }
    fn close_prompt(&self, _id: u64) {}
}

struct Harness {
    host: Arc<McpHost>,
    backend: Arc<Backend>,
    prompts: Arc<Mutex<Vec<Prompt>>>,
    answer: Arc<Mutex<Option<bool>>>,
    /// The UI answers with another digest.
    bad_digest: Arc<AtomicBool>,
    /// The UI answers without having taken Touch ID.
    no_touch_id: Arc<AtomicBool>,
}

fn harness(n: usize, cfg: McpConfig) -> Harness {
    let exec = FakeExec::with(&[]);
    exec.replies
        .lock()
        .unwrap()
        .insert("agent.health", healthy());
    let backend = Arc::new(Backend {
        exec,
        approver: SoftApprover::new(false),
        locked: AtomicBool::new(false),
        running: AtomicBool::new(true),
        paired: Mutex::new(HashSet::new()),
        n,
        limits: Mutex::new(None),
        server_limits: Mutex::new(HashMap::new()),
        confirmed: Mutex::new(Vec::new()),
        saved: Mutex::new(Vec::new()),
    });
    let host = McpHost::new(backend.clone(), cfg);
    let (tx, mut rx) = mpsc::unbounded_channel::<Prompt>();
    host.set_ui(Some(Arc::new(Ui { tx })));
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let answer = Arc::new(Mutex::new(Some(true)));
    let bad_digest = Arc::new(AtomicBool::new(false));
    let no_touch_id = Arc::new(AtomicBool::new(false));
    let (h, p, a) = (host.clone(), prompts.clone(), answer.clone());
    let (bd, nt) = (bad_digest.clone(), no_touch_id.clone());
    tokio::spawn(async move {
        while let Some(prompt) = rx.recv().await {
            let id = prompt.id;
            let digest = if bd.load(Ordering::SeqCst) {
                "0".repeat(64)
            } else {
                prompt.digest.clone()
            };
            lock(&p).push(prompt);
            if let Some(ans) = *lock(&a) {
                h.resolve_prompt(id, ans, &digest, !nt.load(Ordering::SeqCst));
            }
        }
    });
    Harness {
        host,
        backend,
        prompts,
        answer,
        bad_digest,
        no_touch_id,
    }
}

fn peer() -> PeerInfo {
    PeerInfo {
        parent_team: "ABCDE12345".into(),
        parent_signing_id: "com.anthropic.claude-code".into(),
        parent_cdhash: "aa".repeat(20),
        ask_every_time: false,
    }
}

async fn send(
    h: &Harness,
    sess: &mut McpSession,
    body: RequestBody,
) -> Result<ResponseBody, ProtoError> {
    send_on(&h.host, sess, body).await
}

async fn send_on(
    host: &McpHost,
    sess: &mut McpSession,
    body: RequestBody,
) -> Result<ResponseBody, ProtoError> {
    let req = Request {
        v: PROTO_VERSION,
        id: 42,
        body,
    };
    let frame = encode_frame(&req).unwrap();
    let out = host.handle_frame(sess, &frame[4..]).await;
    let n = frame_len(out[..4].try_into().unwrap()).unwrap();
    assert_eq!(n, out.len() - 4);
    let resp: Response = decode_body(&out[4..]).unwrap();
    assert_eq!(resp.id, 42);
    resp.body
}

fn hello(name: &str) -> RequestBody {
    RequestBody::Hello(Hello {
        client_name: name.into(),
        client_version: "1".into(),
        session: "00112233445566778899aabbccddeeff".into(),
    })
}

fn call(tool: &str, args: serde_json::Value) -> RequestBody {
    RequestBody::Call(Call::from_tool(tool, args).unwrap())
}

async fn paired_session(h: &Harness) -> McpSession {
    let mut s = h.host.session(peer());
    let r = send(h, &mut s, hello("claude-code")).await;
    assert!(matches!(r, Ok(ResponseBody::Welcome(_))), "{r:?}");
    s
}

#[tokio::test(flavor = "current_thread")]
async fn pairing_once_then_remembered_and_revocable() {
    let h = harness(2, McpConfig::default());
    let mut s = h.host.session(peer());
    // Calls before Hello are refused.
    assert_eq!(
        send(&h, &mut s, call("fleet_list_servers", json!({}))).await,
        Err(ProtoError::PairingRequired)
    );
    let r = send(&h, &mut s, hello("claude-code")).await;
    let Ok(ResponseBody::Welcome(w)) = r else {
        panic!("{r:?}")
    };
    assert_eq!(w.client_label, "claude-code via com.anthropic.claude-code");
    {
        let p = lock(&h.prompts);
        assert_eq!(p.len(), 1);
        assert!(
            matches!(&p[0].kind, PromptKind::Pairing { identity, ask_every_time: false } if identity.client_name == "claude-code")
        );
    }
    // A second connection of the same client: no prompt.
    let _s2 = paired_session(&h).await;
    assert_eq!(lock(&h.prompts).len(), 1);
    // Another parent process is another client.
    let mut other = h.host.session(PeerInfo {
        parent_team: String::new(),
        parent_signing_id: "evil".into(),
        ..Default::default()
    });
    *lock(&h.answer) = Some(false);
    assert_eq!(
        send(&h, &mut other, hello("claude-code")).await,
        Err(ProtoError::PairingDenied)
    );
    // Revocation applies to live sessions on their next call.
    lock(&h.backend.paired).clear();
    assert_eq!(
        send(&h, &mut s, call("fleet_list_servers", json!({}))).await,
        Err(ProtoError::PairingRequired)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn pause_lock_and_rate_limit() {
    let cfg = McpConfig {
        per_minute: 2,
        ..Default::default()
    };
    let h = harness(2, cfg);
    let mut s = paired_session(&h).await;
    h.host.set_paused(true);
    assert_eq!(
        send(&h, &mut s, call("fleet_list_servers", json!({}))).await,
        Err(ProtoError::Paused)
    );
    assert_eq!(
        send(&h, &mut h.host.session(peer()), hello("claude-code")).await,
        Err(ProtoError::Paused)
    );
    h.host.set_paused(false);
    h.backend.locked.store(true, Ordering::SeqCst);
    assert_eq!(
        send(&h, &mut s, call("fleet_list_servers", json!({}))).await,
        Err(ProtoError::Locked)
    );
    h.backend.locked.store(false, Ordering::SeqCst);
    for _ in 0..2 {
        assert!(
            send(&h, &mut s, call("fleet_list_servers", json!({})))
                .await
                .is_ok()
        );
    }
    assert!(matches!(
        send(&h, &mut s, call("fleet_list_servers", json!({}))).await,
        Err(ProtoError::RateLimited { .. })
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn pause_declines_waiting_prompts() {
    let h = harness(8, McpConfig::default());
    let mut s = paired_session(&h).await;
    *lock(&h.answer) = None; // operator doesn't answer
    let host = h.host.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        host.set_paused(true);
    });
    let servers: Vec<String> = (0..8).map(|i| sid(i).to_string()).collect();
    let r = send(
        &h,
        &mut s,
        call(
            "service_action",
            json!({"servers": servers, "unit": "nginx.service", "action": "restart"}),
        ),
    )
    .await;
    assert_eq!(r, Err(ProtoError::Paused));
    assert!(h.backend.exec.calls().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn validates_before_anything_runs() {
    let h = harness(2, McpConfig::default());
    let mut s = paired_session(&h).await;
    let r = send(
        &h,
        &mut s,
        call(
            "service_action",
            json!({"servers": [sid(0).to_string()], "unit": "fleet-exec.service", "action": "stop"}),
        ),
    )
    .await;
    assert!(matches!(r, Err(ProtoError::InvalidArgument { .. })));
    let r = send(
        &h,
        &mut s,
        call("firewall_get", json!({"server": "srv_99999999"})),
    )
    .await;
    assert!(matches!(r, Err(ProtoError::UnknownServer { .. })));
    let r = send(
        &h,
        &mut s,
        call(
            "processes_list",
            json!({"server": sid(0).to_string(), "sort": "cpu", "limit": 0}),
        ),
    )
    .await;
    assert!(matches!(r, Err(ProtoError::InvalidArgument { .. })));
    assert!(h.backend.exec.calls().is_empty());
    // Core not started.
    h.backend.running.store(false, Ordering::SeqCst);
    let r = send(
        &h,
        &mut s,
        call("firewall_get", json!({"server": sid(0).to_string()})),
    )
    .await;
    assert_eq!(r, Err(ProtoError::NotRunning));
}

#[tokio::test(flavor = "current_thread")]
async fn wide_bulk_needs_approval_and_runs_canary_first() {
    let h = harness(8, McpConfig::default());
    let mut s = paired_session(&h).await;
    let servers: Vec<String> = (0..8).map(|i| sid(i).to_string()).collect();
    let args = json!({"servers": servers, "op": {"op": "unit", "unit": "nginx.service", "action": "restart"}});

    *lock(&h.answer) = Some(false);
    let r = send(&h, &mut s, call("bulk_run", args.clone())).await;
    assert_eq!(r, Err(ProtoError::ApprovalDenied));
    assert!(h.backend.exec.calls().is_empty());

    *lock(&h.answer) = Some(true);
    let r = send(&h, &mut s, call("bulk_run", args)).await;
    let Ok(ResponseBody::Tool(out)) = r else {
        panic!("{r:?}")
    };
    assert_eq!(out.summary["succeeded"], 8);
    assert_eq!(out.summary["canary"], true);
    let prompts = lock(&h.prompts).clone();
    let PromptKind::Approval {
        servers,
        elevated,
        op,
        client,
        ..
    } = &prompts.last().unwrap().kind
    else {
        panic!()
    };
    assert_eq!(servers.len(), 8);
    assert!(!elevated);
    assert_eq!(op, "unit.restart");
    assert_eq!(client, "claude-code");
    let calls = h.backend.exec.calls();
    // Canary first, then its health check, then the rest.
    assert_eq!(calls[0], (sid(0), "unit.restart".into(), false));
    assert_eq!(calls[1].1, "agent.health");
    // Every command is attributed to the AI client.
    assert!(h.backend.exec.actors.lock().unwrap().iter().all(|a| matches!(
        a,
        Actor::Ai { client, session } if client.as_str() == "claude-code" && session[0] == 0x00 && session[1] == 0x11
    )));
    // Narrow changes (≤ threshold) run without a prompt.
    let before = lock(&h.prompts).len();
    let r = send(
        &h,
        &mut s,
        call(
            "service_action",
            json!({"servers": [sid(1).to_string()], "unit": "nginx.service", "action": "reload"}),
        ),
    )
    .await;
    assert!(r.is_ok());
    assert_eq!(lock(&h.prompts).len(), before);
}

#[tokio::test(flavor = "current_thread")]
async fn elevated_needs_prompt_and_root_approval() {
    let h = harness(3, McpConfig::default());
    let mut s = paired_session(&h).await;
    let servers: Vec<String> = (0..2).map(|i| sid(i).to_string()).collect();
    let r = send(
        &h,
        &mut s,
        call(
            "shell_exec",
            json!({"servers": servers, "user": "deploy", "command": "uptime"}),
        ),
    )
    .await;
    assert!(r.is_ok(), "{r:?}");
    let prompts = lock(&h.prompts).clone();
    assert!(matches!(
        &prompts.last().unwrap().kind,
        PromptKind::Approval { elevated: true, .. }
    ));
    let asked = h.backend.approver.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].1.len(), 2);
    let shell_calls: Vec<_> = h
        .backend
        .exec
        .calls()
        .into_iter()
        .filter(|c| c.1 == "shell.exec")
        .collect();
    assert_eq!(shell_calls.len(), 2);
    assert!(
        shell_calls.iter().all(|c| c.2),
        "each command carries the approval"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn server_text_is_untrusted_redacted_and_secret_files_refused() {
    let h = harness(1, McpConfig::default());
    h.backend.exec.replies.lock().unwrap().insert(
        "config.paths.get",
        Payload::ConfigPaths(ConfigPaths {
            builtin_tracked: vec!["/etc/app.conf password=hunter2 \u{1b}[2J".into()],
            builtin_secret: vec!["/etc/shadow".into(), "/etc/ssl/private".into()],
            tracked: vec![],
            secret: vec!["/etc/app/*.key".into()],
            version: 1,
        }),
    );
    let mut s = paired_session(&h).await;
    let server = sid(0).to_string();
    for path in [
        "/etc/shadow",
        "/etc/ssl/private/site.pem",
        "/etc/app/tls.key",
    ] {
        let r = send(
            &h,
            &mut s,
            call(
                "config_diff",
                json!({"server": server, "path": path, "from": 1}),
            ),
        )
        .await;
        assert!(
            matches!(r, Err(ProtoError::Unsupported { .. })),
            "{path}: {r:?}"
        );
    }
    assert!(!h.backend.exec.calls().iter().any(|c| c.1 == "config.diff"));
    // A permitted file goes through.
    let r = send(
        &h,
        &mut s,
        call(
            "config_diff",
            json!({"server": server, "path": "/etc/nginx/nginx.conf", "from": 1}),
        ),
    )
    .await;
    assert!(r.is_ok());

    // Returned server text lands in `untrusted`, redacted and escaped.
    let text = Payload::ConfigPaths(ConfigPaths {
        builtin_tracked: vec!["password=hunter2 \u{1b}[2J".into()],
        builtin_secret: vec![],
        tracked: vec![],
        secret: vec![],
        version: 1,
    });
    h.backend
        .exec
        .replies
        .lock()
        .unwrap()
        .insert("processes.list", text);
    let r = send(
        &h,
        &mut s,
        call("processes_list", json!({"server": server, "sort": "cpu"})),
    )
    .await;
    let Ok(ResponseBody::Tool(out)) = r else {
        panic!("{r:?}")
    };
    assert_eq!(out.summary["ok"], true);
    assert_eq!(out.untrusted.len(), 1);
    let item = &out.untrusted[0];
    assert_eq!(item.server, server);
    assert_eq!(item.source, "processes.list");
    assert!(!item.text.contains("hunter2"));
    assert!(!item.text.contains('\u{1b}'));
    assert!(item.redactions >= 1);
    assert!(!out.summary.to_string().contains("hunter2"));
}

#[tokio::test(flavor = "current_thread")]
async fn version_and_malformed_frames() {
    let h = harness(1, McpConfig::default());
    let mut s = h.host.session(peer());
    let frame = encode_frame(&Request {
        v: 9,
        id: 42,
        body: hello("x"),
    })
    .unwrap();
    let out = h.host.handle_frame(&mut s, &frame[4..]).await;
    let resp: Response = decode_body(&out[4..]).unwrap();
    assert_eq!(resp.body, Err(ProtoError::Version { app: 1, client: 9 }));
    let out = h.host.handle_frame(&mut s, b"{not json").await;
    let resp: Response = decode_body(&out[4..]).unwrap();
    assert!(matches!(resp.body, Err(ProtoError::InvalidArgument { .. })));
    // Firewall apply: an invalid ruleset is refused before anything runs.
    let mut s = paired_session(&h).await;
    let r = send(
        &h,
        &mut s,
        call(
            "firewall_apply",
            json!({"server": sid(0).to_string(), "ruleset": {}, "expected_version": 1}),
        ),
    )
    .await;
    assert!(matches!(r, Err(ProtoError::InvalidArgument { .. })));
}

#[tokio::test(flavor = "current_thread")]
async fn firewall_apply_carries_the_ai_version_and_is_confirmed() {
    use fleet_proto::args::{FirewallMode, FirewallRuleSet};
    use fleet_proto::payload::{ChangeKind, PendingChange};
    let h = harness(1, McpConfig::default());
    h.backend.exec.replies.lock().unwrap().insert(
        "firewall.apply",
        Payload::ChangePending {
            change: PendingChange {
                change_id: [3; 16],
                kind: ChangeKind::Firewall,
                op_tag: 401,
                created_ms: 1,
                deadline_ms: 2,
                new_version: Some(8),
            },
            inner: None,
        },
    );
    let mut s = paired_session(&h).await;
    let ruleset = serde_json::to_value(FirewallRuleSet {
        mode: FirewallMode::BansOnly,
        rules: vec![],
    })
    .unwrap();
    let r = send(
        &h,
        &mut s,
        call(
            "firewall_apply",
            json!({"server": sid(0).to_string(), "ruleset": ruleset, "expected_version": 7}),
        ),
    )
    .await;
    let Ok(ResponseBody::Tool(out)) = r else {
        panic!("{r:?}")
    };
    assert_eq!(out.summary["succeeded"], 1);
    let status = out.summary["servers"][0]["status"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(status.contains("confirmed"), "{status}");
    let sent = h.backend.exec.sent.lock().unwrap().clone();
    assert_eq!(
        sent,
        vec![(sid(0), "firewall.apply".to_string(), Some(7), false)]
    );
    assert!(!h.backend.exec.calls().iter().any(|c| c.1 == "firewall.get"));
    let confirmed = lock(&h.backend.confirmed).clone();
    assert_eq!(confirmed.len(), 1);
    assert_eq!((&confirmed[0].0, confirmed[0].1), (&sid(0), [3; 16]));
    // Confirmed as the AI, not as the operator.
    assert!(
        matches!(&confirmed[0].2, Actor::Ai { client, .. } if client.as_str() == "claude-code"),
        "{:?}",
        confirmed[0].2
    );
}

#[tokio::test(flavor = "current_thread")]
async fn pushed_policy_limits_apply() {
    let h = harness(3, McpConfig::default());
    *lock(&h.backend.limits) = Some(AiLimits {
        commands_per_minute: 2,
        bulk_confirm_above: 1,
    });
    let mut s = paired_session(&h).await;
    let before = lock(&h.prompts).len();
    // Two servers: above the policy's threshold of 1 (default 5).
    let r = send(
        &h,
        &mut s,
        call(
            "service_action",
            json!({"servers": [sid(0).to_string(), sid(1).to_string()], "unit": "nginx.service", "action": "reload"}),
        ),
    )
    .await;
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(lock(&h.prompts).len(), before + 1);
    // The policy's rate (2 per minute), not the default 60.
    assert!(
        send(&h, &mut s, call("fleet_list_servers", json!({})))
            .await
            .is_ok()
    );
    assert!(matches!(
        send(&h, &mut s, call("fleet_list_servers", json!({}))).await,
        Err(ProtoError::RateLimited { .. })
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn serve_over_a_byte_stream() {
    let h = harness(3, McpConfig::default());
    let (client, server) = tokio::io::duplex(64 * 1024);
    let host = h.host.clone();
    let task = tokio::spawn(async move { host.serve(peer(), server).await });
    let (mut rd, mut wr) = tokio::io::split(client);
    async fn rt<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        rd: &mut R,
        wr: &mut W,
        id: u64,
        body: RequestBody,
    ) -> Response {
        let f = encode_frame(&Request {
            v: PROTO_VERSION,
            id,
            body,
        })
        .unwrap();
        wr.write_all(&f).await.unwrap();
        let mut hdr = [0u8; 4];
        rd.read_exact(&mut hdr).await.unwrap();
        let mut b = vec![0u8; frame_len(hdr).unwrap()];
        rd.read_exact(&mut b).await.unwrap();
        decode_body(&b).unwrap()
    }
    let r = rt(&mut rd, &mut wr, 1, hello("cursor")).await;
    assert!(matches!(r.body, Ok(ResponseBody::Welcome(_))));
    let r = rt(
        &mut rd,
        &mut wr,
        2,
        call("fleet_list_servers", json!({"tag": "even"})),
    )
    .await;
    assert_eq!(r.id, 2);
    let Ok(ResponseBody::Tool(out)) = r.body else {
        panic!()
    };
    assert_eq!(out.summary["servers"].as_array().unwrap().len(), 2);
    assert!(out.untrusted.is_empty());
    let r = rt(
        &mut rd,
        &mut wr,
        3,
        call(
            "fleet_search",
            json!({"kind": "packages", "term": "openssl"}),
        ),
    )
    .await;
    let Ok(ResponseBody::Tool(out)) = r.body else {
        panic!("{:?}", r.body)
    };
    assert_eq!(out.summary["succeeded"], 3);
    assert_eq!(out.summary["canary"], false, "reads don't need a canary");
    // Oversized header: the host drops the connection.
    wr.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
    assert!(matches!(task.await.unwrap(), Err(FrameError::TooLarge(_))));
    let _ = Behave::Hang;
}

fn servers(range: std::ops::Range<usize>) -> Vec<String> {
    range.map(|i| sid(i).to_string()).collect()
}

fn restart(servers: Vec<String>) -> RequestBody {
    call(
        "service_action",
        json!({"servers": servers, "unit": "nginx.service", "action": "restart"}),
    )
}

#[test]
fn interpreters_and_shells_are_recognized() {
    for id in [
        "com.apple.zsh",
        "com.apple.bash",
        "/usr/bin/python3.12",
        "org.python.python",
        "python3",
        "node",
        "com.apple.osascript",
        "env",
        "perl5.34",
    ] {
        assert!(is_interpreter(id), "{id}");
    }
    for id in [
        "com.anthropic.claude-code",
        "com.todesktop.230313mzl4w4u92",
        "com.jetbrains.rubymine",
        "com.jetbrains.PhpStorm",
        "com.microsoft.VSCode",
    ] {
        assert!(!is_interpreter(id), "{id}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn interpreter_parents_are_asked_every_time_and_cdhash_binds_pairing() {
    let h = harness(1, McpConfig::default());
    let zsh = PeerInfo {
        parent_team: "ABCDE12345".into(),
        parent_signing_id: "com.apple.zsh".into(),
        parent_cdhash: "bb".repeat(20),
        ask_every_time: false,
    };
    for n in 1..=2 {
        let mut s = h.host.session(zsh.clone());
        let r = send(&h, &mut s, hello("claude-code")).await;
        assert!(matches!(r, Ok(ResponseBody::Welcome(_))), "{r:?}");
        assert_eq!(lock(&h.prompts).len(), n);
        // Works for this connection although nothing was stored.
        assert!(
            send(&h, &mut s, call("fleet_list_servers", json!({})))
                .await
                .is_ok()
        );
    }
    assert!(lock(&h.backend.saved).is_empty());
    assert!(lock(&h.prompts).iter().all(|p| matches!(
        &p.kind,
        PromptKind::Pairing {
            ask_every_time: true,
            ..
        }
    )));
    // Swift's verdict alone is enough.
    let flagged = PeerInfo {
        ask_every_time: true,
        ..peer()
    };
    assert!(flagged.ask_every_time());
    assert!(!peer().ask_every_time());

    // A persisted pairing is bound to the parent's cdhash.
    let _s = paired_session(&h).await;
    let rec = lock(&h.backend.saved).clone();
    assert_eq!(rec.len(), 1);
    let before = lock(&h.prompts).len();
    let _s = paired_session(&h).await;
    assert_eq!(lock(&h.prompts).len(), before, "same build: remembered");
    let mut updated = h.host.session(PeerInfo {
        parent_cdhash: "cc".repeat(20),
        ..peer()
    });
    let r = send(&h, &mut updated, hello("claude-code")).await;
    assert!(matches!(r, Ok(ResponseBody::Welcome(_))));
    assert_eq!(
        lock(&h.prompts).len(),
        before + 1,
        "new cdhash: asked again"
    );
    let last = lock(&h.prompts).last().unwrap().clone();
    let PromptKind::Pairing { identity, .. } = &last.kind else {
        panic!()
    };
    assert_eq!(last.digest, identity.key());
}

#[tokio::test(flavor = "current_thread")]
async fn one_pairing_prompt_at_a_time() {
    let h = harness(1, McpConfig::default());
    *lock(&h.answer) = None;
    let host = h.host.clone();
    let first = tokio::spawn(async move {
        let mut s = host.session(peer());
        send_on(&host, &mut s, hello("first")).await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut s = h.host.session(peer());
    assert_eq!(
        send(&h, &mut s, hello("second")).await,
        Err(ProtoError::PairingRequired)
    );
    assert_eq!(lock(&h.prompts).len(), 1);
    // Answering the first frees the slot.
    let id = lock(&h.prompts)[0].id;
    let digest = lock(&h.prompts)[0].digest.clone();
    assert!(h.host.resolve_prompt(id, true, &digest, true));
    assert!(matches!(first.await.unwrap(), Ok(ResponseBody::Welcome(_))));
    *lock(&h.answer) = Some(true);
    assert!(matches!(
        send(&h, &mut s, hello("second")).await,
        Ok(ResponseBody::Welcome(_))
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn approvals_are_bound_to_the_digest_and_need_touch_id() {
    let h = harness(8, McpConfig::default());
    let mut s = paired_session(&h).await;
    h.bad_digest.store(true, Ordering::SeqCst);
    assert_eq!(
        send(&h, &mut s, restart(servers(0..8))).await,
        Err(ProtoError::ApprovalDenied)
    );
    h.bad_digest.store(false, Ordering::SeqCst);
    h.no_touch_id.store(true, Ordering::SeqCst);
    assert_eq!(
        send(&h, &mut s, restart(servers(0..8))).await,
        Err(ProtoError::ApprovalDenied)
    );
    assert!(h.backend.exec.calls().is_empty());
    // Pairing needs Touch ID too.
    let mut other = h.host.session(PeerInfo {
        parent_signing_id: "com.example.other".into(),
        ..peer()
    });
    assert_eq!(
        send(&h, &mut other, hello("other")).await,
        Err(ProtoError::PairingDenied)
    );
    // Elevated: the root key's Touch ID follows, the prompt alone suffices.
    let r = send(
        &h,
        &mut s,
        call(
            "shell_exec",
            json!({"servers": servers(0..1), "user": "deploy", "command": "uptime"}),
        ),
    )
    .await;
    assert!(r.is_ok(), "{r:?}");
    // resolve_prompt reports an answer it turned into a denial.
    h.no_touch_id.store(false, Ordering::SeqCst);
    *lock(&h.answer) = None;
    let host = h.host.clone();
    let mut s2 = paired_session(&h).await;
    let pending =
        tokio::spawn(async move { send_on(&host, &mut s2, restart(servers(0..8))).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let p = lock(&h.prompts).last().unwrap().clone();
    assert_eq!(p.digest.len(), 64);
    assert!(!h.host.resolve_prompt(p.id, true, "nope", true));
    assert!(!h.host.resolve_prompt(p.id, true, &p.digest, true), "gone");
    assert_eq!(pending.await.unwrap(), Err(ProtoError::ApprovalDenied));
}

#[tokio::test(flavor = "current_thread")]
async fn approval_details_are_complete_or_refused() {
    let yaml = format!("services:\n{}  end: MARKER\n", "  x: y\n".repeat(1000));
    let args = json!({"servers": servers(0..8), "op": {
        "op": "compose_deploy", "project": "app", "compose_yaml": yaml, "pull": false
    }});
    let h = harness(8, McpConfig::default());
    let mut s = paired_session(&h).await;
    let r = send(&h, &mut s, call("bulk_run", args.clone())).await;
    assert!(r.is_ok(), "{r:?}");
    let p = lock(&h.prompts).last().unwrap().clone();
    let PromptKind::Approval {
        details, servers, ..
    } = &p.kind
    else {
        panic!()
    };
    assert!(details.len() > 7000);
    assert!(details.contains("MARKER"), "never cut");
    assert_eq!(servers.len(), 8);

    let h = harness(
        8,
        McpConfig {
            max_approval_details: 1000,
            ..Default::default()
        },
    );
    let mut s = paired_session(&h).await;
    let before = lock(&h.prompts).len();
    assert_eq!(
        send(&h, &mut s, call("bulk_run", args)).await,
        Err(ProtoError::InvalidArgument {
            field: DETAILS_TOO_LARGE.into()
        })
    );
    assert_eq!(lock(&h.prompts).len(), before, "no prompt");
    assert!(h.backend.exec.calls().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn pause_cancels_running_calls() {
    let h = harness(2, McpConfig::default());
    h.backend
        .exec
        .behave
        .lock()
        .unwrap()
        .insert(sid(0), Behave::Hang);
    let mut s = paired_session(&h).await;
    let host = h.host.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        host.set_paused(true);
    });
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        send(&h, &mut s, restart(servers(0..1))),
    )
    .await
    .expect("cancelled, not hanging");
    assert_eq!(r, Err(ProtoError::Paused));
    assert!(lock(&h.host.runs).is_empty());
    // A single read too.
    h.host.set_paused(false);
    h.backend
        .exec
        .replies
        .lock()
        .unwrap()
        .remove("firewall.get");
    let host = h.host.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        host.set_paused(true);
    });
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        send(
            &h,
            &mut s,
            call("firewall_get", json!({"server": sid(0).to_string()})),
        ),
    )
    .await
    .expect("cancelled, not hanging");
    assert_eq!(r, Err(ProtoError::Paused));
    assert!(lock(&h.host.runs).is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn ai_approver_checks_pause_before_touch_id_and_names_the_client() {
    let h = harness(1, McpConfig::default());
    let op = Op::UnitRestart {
        unit: fleet_proto::args::UnitName::new("nginx.service").unwrap(),
    };
    let ai = AiApprover {
        host: Arc::downgrade(&h.host),
        inner: h.backend.approver.clone(),
        client: "claude-code".into(),
        tool: "bulk_run".into(),
        op: op.clone(),
        escalation: false,
        cancel: CancelToken::new(),
    };
    let items = vec![ApprovalItem {
        server_id: sid(0),
        op_digest: fleet_crypto::approval::op_digest(&op, None),
    }];
    assert_eq!(ai.approve("unit.restart", &items).unwrap().len(), 1);
    ai.approve(bulk::APPROVAL_REFRESH_LABEL, &items).unwrap();
    let asked: Vec<String> = h
        .backend
        .approver
        .asked
        .lock()
        .unwrap()
        .iter()
        .map(|a| a.0.clone())
        .collect();
    assert_eq!(
        asked,
        vec![
            "AI (claude-code): unit.restart".to_string(),
            "AI (claude-code): unit.restart: continue bulk run".to_string(),
        ]
    );
    h.host.set_paused(true);
    assert!(matches!(
        ai.approve("unit.restart", &items),
        Err(ApproveError::Cancelled)
    ));
    h.host.set_paused(false);
    ai.cancel.cancel();
    assert!(matches!(
        ai.approve("unit.restart", &items),
        Err(ApproveError::Cancelled)
    ));
    assert_eq!(
        h.backend.approver.asked.lock().unwrap().len(),
        2,
        "no Touch ID"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn escalations_ask_the_operator_then_the_root_key() {
    let h = harness(2, McpConfig::default());
    h.backend.exec.escalates.lock().unwrap().push(sid(0));
    let mut s = paired_session(&h).await;
    let deploy = || {
        call(
            "compose_deploy",
            json!({"server": sid(0).to_string(), "project": "app",
                   "compose_yaml": "services:\n  web:\n    image: nginx\n", "pull": false}),
        )
    };
    let r = send(&h, &mut s, deploy()).await;
    let Ok(ResponseBody::Tool(out)) = r else {
        panic!("{r:?}")
    };
    assert_eq!(out.summary["succeeded"], 1, "{}", out.summary);
    let p = lock(&h.prompts).last().unwrap().clone();
    assert!(
        matches!(&p.kind, PromptKind::Approval { escalation: true, elevated: true, op, details, .. }
            if op == "compose.deploy" && details.contains("image: nginx")),
        "{p:?}"
    );
    let asked = h.backend.approver.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 1);
    assert!(
        asked[0].0.starts_with("AI (claude-code): compose.deploy"),
        "{}",
        asked[0].0
    );
    // Declined by the operator: no root key prompt, the change fails.
    *lock(&h.answer) = Some(false);
    let r = send(&h, &mut s, deploy()).await;
    let Ok(ResponseBody::Tool(out)) = r else {
        panic!("{r:?}")
    };
    assert_eq!(out.summary["failed"], 1, "{}", out.summary);
    assert_eq!(h.backend.approver.asked.lock().unwrap().len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn split_wide_changes_count_together() {
    let h = harness(8, McpConfig::default());
    let mut s = paired_session(&h).await;
    let prompts = || lock(&h.prompts).len();
    let base = prompts();
    assert!(send(&h, &mut s, restart(servers(0..3))).await.is_ok());
    assert_eq!(prompts(), base, "3 ≤ 5");
    // Another op is counted apart.
    let reload = call(
        "service_action",
        json!({"servers": servers(3..6), "unit": "nginx.service", "action": "reload"}),
    );
    assert!(send(&h, &mut s, reload).await.is_ok());
    assert_eq!(prompts(), base);
    // 3 more restarts: 6 distinct servers within the window.
    assert!(send(&h, &mut s, restart(servers(3..6))).await.is_ok());
    assert_eq!(prompts(), base + 1);
    // The operator saw them: the window starts over.
    assert!(send(&h, &mut s, restart(servers(6..8))).await.is_ok());
    assert_eq!(prompts(), base + 1);
    // Repeating the same servers doesn't add up.
    assert!(send(&h, &mut s, restart(servers(6..8))).await.is_ok());
    assert_eq!(prompts(), base + 1);
    // Outside the window nothing adds up.
    let h = harness(
        8,
        McpConfig {
            wide_window: Duration::from_millis(1),
            ..Default::default()
        },
    );
    let mut s = paired_session(&h).await;
    let base = lock(&h.prompts).len();
    assert!(send(&h, &mut s, restart(servers(0..3))).await.is_ok());
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert!(send(&h, &mut s, restart(servers(3..6))).await.is_ok());
    assert_eq!(lock(&h.prompts).len(), base);
}

#[tokio::test(flavor = "current_thread")]
async fn servers_without_a_policy_copy_use_the_defaults() {
    let h = harness(8, McpConfig::default());
    lock(&h.backend.server_limits).insert(
        sid(0),
        AiLimits {
            commands_per_minute: 1000,
            bulk_confirm_above: 100,
        },
    );
    assert_eq!(h.host.per_minute(), 60);
    assert_eq!(h.host.bulk_confirm_above(&[sid(0)]), 100);
    assert_eq!(h.host.bulk_confirm_above(&[sid(0), sid(1)]), 5);
    let mut s = paired_session(&h).await;
    let base = lock(&h.prompts).len();
    assert!(send(&h, &mut s, restart(servers(0..6))).await.is_ok());
    assert_eq!(lock(&h.prompts).len(), base + 1);
}

#[tokio::test(flavor = "current_thread")]
async fn shell_output_is_rendered_as_text_then_redacted() {
    use fleet_proto::payload::ShellResult;
    let h = harness(1, McpConfig::default());
    h.backend.exec.replies.lock().unwrap().insert(
        "processes.list",
        Payload::ShellResult(ShellResult {
            exit_code: Some(0),
            stdout: b"run --password hunter2 -v\n{\"api_key\": \"k 1\"}\nexport TOKEN='t t'\npassword: two words\nok \xff\xe2\x80\x8b\n".to_vec(),
            stderr: vec![],
            truncated: false,
            timed_out: false,
        }),
    );
    let mut s = paired_session(&h).await;
    let r = send(
        &h,
        &mut s,
        call(
            "processes_list",
            json!({"server": sid(0).to_string(), "sort": "cpu"}),
        ),
    )
    .await;
    let Ok(ResponseBody::Tool(out)) = r else {
        panic!("{r:?}")
    };
    let t = &out.untrusted[0].text;
    assert!(t.contains("stdout:"), "{t}");
    assert!(t.contains("--password [REDACTED] -v"), "{t}");
    for secret in ["hunter2", "k 1", "t t", "two words"] {
        assert!(!t.contains(secret), "{secret}: {t}");
    }
    assert!(!t.contains("ShellResult") && !t.contains("[114"), "{t}");
    assert!(t.contains("\\u{200b}") && t.contains('\u{FFFD}'), "{t}");
    assert_eq!(out.untrusted[0].redactions, 4);
}

#[test]
fn confirm_failures_are_fixed_codes() {
    assert_eq!(ConfirmFailure::Reverted.code(), "reverted");
    assert_eq!(
        ConfirmFailure::Agent(ErrorCode::NotFound).code(),
        "agent_NotFound"
    );
    assert_eq!(ConfirmFailure::Unavailable.code(), "unavailable");
}
