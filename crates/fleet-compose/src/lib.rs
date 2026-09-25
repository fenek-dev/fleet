//! `compose.deploy` validation (design §4.2 "Compose validation").
//!
//! Pure: no I/O, so the Mac runs exactly the same check to know whether a
//! deploy needs Touch ID. [`validate`] parses the file with an event-level
//! YAML parser and builds its own small tree, refusing (as errors, not
//! findings) everything that could hide a key from a structural check:
//!
//! - anchors and aliases (no billion-laughs, no shared nodes), tags, merge
//!   keys (`<<`), duplicate keys, non-scalar keys, more than one document;
//! - input over [`MAX_BYTES`], nesting deeper than [`MAX_DEPTH`], more than
//!   [`MAX_NODES`] nodes.
//!
//! It then reports every feature on the deny-list as a [`Finding`]; any
//! finding makes the deploy Elevated (root approval), errors make it
//! `InvalidArgument`. Deny-list: `privileged` (service and build),
//! `cap_add` outside [`CAP_ALLOW`], `pid`/`ipc`/`network_mode`/`userns_mode`/
//! `cgroup: host`, a network named or driven `host`, `devices`,
//! `device_cgroup_rules`, `security_opt` other than `no-new-privileges` or
//! `apparmor=docker-default`, bind mounts (short and long syntax, relative
//! paths resolved against `/srv/<project>/`, `~`, volume `driver_opts.device`)
//! outside `/srv/<project>/`, host files read by Compose (`env_file`,
//! `label_file`, secret/config `file`, build contexts and Dockerfiles)
//! outside it, and `include`/`extends.file` (content not validated here).
//! Also: `pid`/`ipc`/`network_mode` other than `none`, `bridge`, `private`,
//! `shareable`, `service:<service in this file>` (and, for `network_mode`,
//! `default` or a network declared here), `uts: host`; `volumes_from` other
//! than `service:<service in this file>[:ro|:rw]`; `use_api_socket` unless
//! literally false; `post_start`/`pre_stop` hooks that are privileged or
//! carry `$` in `command`/`environment`; `build.cache_from`/`cache_to`
//! `type=local` `src`/`dest` outside the project; `build.ssh` entries with
//! a path; `gpus` and `deploy.resources.reservations.devices`; `provider`,
//! `cgroup_parent`, `runtime` other than `runc`; top-level volumes that are
//! `external` or named outside `<project>_`. Bind sources must be strictly
//! below `/srv/<project>/` and not its `compose.yaml` or `.env`.
//! A `$` in any of these values is a finding too: interpolation reads
//! `.env` and the environment, which this check can't see.
//!
//! **Caller obligations** (the future `compose.deploy` handler): write the
//! file as `/srv/<project>/compose.yaml` and run Compose with that single
//! `-f` and `--project-directory`, so no `compose.override.yaml` or
//! `COMPOSE_FILE` from `.env` is merged in; and check that `/srv/<project>`
//! contains no symlink a relative bind source could resolve through
//! (lexical resolution here can't see the filesystem).
#![forbid(unsafe_code)]

use fleet_proto::args::ComposeProject;
use std::collections::HashSet;
use yaml_rust2::parser::{Event, Parser};

pub const MAX_BYTES: usize = fleet_proto::args::ComposeFile::MAX_BYTES;
pub const MAX_DEPTH: usize = 32;
pub const MAX_NODES: usize = 100_000;

/// Capabilities a container may add without Elevated approval.
pub const CAP_ALLOW: &[&str] = &[
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "SETGID",
    "SETUID",
    "NET_BIND_SERVICE",
    "KILL",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingKind {
    Privileged,
    CapAdd,
    /// `pid`/`ipc`/`network_mode`/`userns_mode`/`cgroup: host`, `build.network: host`.
    HostNamespace,
    /// A top-level network that is the host network.
    HostNetwork,
    /// `devices`, `device_cgroup_rules`.
    Devices,
    SecurityOpt,
    /// Bind mount (or bind-backed volume, unknown mount type) outside the
    /// project directory.
    BindMount,
    /// A host file Compose reads (env/label file, secret, config, build
    /// context, Dockerfile) outside the project directory.
    HostFile,
    /// `include` or `extends.file`: another file this check doesn't see.
    ExternalFile,
    /// `$` in a checked value: resolved from `.env`/environment later.
    Interpolated,
    /// `use_api_socket`: the Engine API socket inside the container.
    DockerSocket,
    /// `volumes_from` a container or service not defined in this file.
    ForeignContainer,
    /// A top-level volume that is `external` or named outside the project.
    ExternalVolume,
    /// `runtime` other than `runc`, `cgroup_parent`, `provider`.
    Runtime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// `None` for top-level keys.
    pub service: Option<String>,
    pub kind: FindingKind,
    /// The key and the offending value, for the approval prompt.
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposeError {
    TooLarge,
    Syntax {
        line: usize,
        col: usize,
    },
    TooDeep,
    TooManyNodes,
    Empty,
    MultipleDocuments,
    Anchor,
    Alias,
    Tag,
    MergeKey,
    NonScalarKey,
    DuplicateKey(String),
    /// A value of the wrong type at this path (e.g. `services` not a map).
    Shape(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ComposeVerdict {
    /// Parsed and well-formed (`errors` is empty).
    pub ok: bool,
    /// Deny-listed features: deploying needs a root approval.
    pub requires_elevated: Vec<Finding>,
    pub errors: Vec<ComposeError>,
    /// Host paths inside `/srv/<project>` the file uses (bind sources,
    /// env/label/secret/config files, build contexts), lexically
    /// normalized. The deploy handler refuses one that resolves through a
    /// symlink.
    pub host_paths: Vec<String>,
}

impl ComposeVerdict {
    /// Well-formed but uses a deny-listed feature.
    pub fn escalates(&self) -> bool {
        self.ok && !self.requires_elevated.is_empty()
    }
}

/// The parsed document: scalars keep only their text (style is irrelevant:
/// Compose converts quoted and plain values the same way).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Scalar(String),
    Seq(Vec<Node>),
    Map(Vec<(String, Node)>),
}

impl Node {
    fn is_null(&self) -> bool {
        matches!(self, Node::Scalar(s) if matches!(s.as_str(), "" | "~" | "null" | "Null" | "NULL"))
    }

    /// Explicitly false (or absent/null). Anything else counts as true.
    fn is_false(&self) -> bool {
        self.is_null()
            || matches!(self, Node::Scalar(s) if matches!(
                s.trim(),
                "false" | "False" | "FALSE" | "no" | "No" | "NO" | "off" | "Off" | "OFF" | "0"
            ))
    }

    /// Literally `false` (null and other falsy spellings don't count).
    fn is_literal_false(&self) -> bool {
        matches!(self, Node::Scalar(s) if matches!(s.trim(), "false" | "False" | "FALSE"))
    }

    /// Any scalar (or map key) below this node contains `$`.
    fn has_dollar(&self) -> bool {
        match self {
            Node::Scalar(s) => s.contains('$'),
            Node::Seq(items) => items.iter().any(Node::has_dollar),
            Node::Map(m) => m.iter().any(|(k, v)| k.contains('$') || v.has_dollar()),
        }
    }

    fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Node::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn scalar(&self) -> Option<&str> {
        match self {
            Node::Scalar(s) => Some(s),
            _ => None,
        }
    }

    /// A scalar or a sequence of scalars; `None` for other shapes.
    fn scalars(&self) -> Option<Vec<&str>> {
        match self {
            _ if self.is_null() => Some(Vec::new()),
            Node::Scalar(s) => Some(vec![s]),
            Node::Seq(items) => items.iter().map(Node::scalar).collect(),
            Node::Map(_) => None,
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            Node::Seq(v) => v.is_empty(),
            Node::Map(m) => m.is_empty(),
            Node::Scalar(_) => self.is_null(),
        }
    }
}

struct Loader<'a> {
    p: Parser<std::str::Chars<'a>>,
    nodes: usize,
}

impl Loader<'_> {
    fn next(&mut self) -> Result<Event, ComposeError> {
        let (ev, _) = self.p.next_token().map_err(|e| ComposeError::Syntax {
            line: e.marker().line(),
            col: e.marker().col(),
        })?;
        Ok(ev)
    }

    fn node(&mut self, ev: Event, depth: usize) -> Result<Node, ComposeError> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(ComposeError::TooManyNodes);
        }
        if depth > MAX_DEPTH {
            return Err(ComposeError::TooDeep);
        }
        match ev {
            Event::Alias(_) => Err(ComposeError::Alias),
            Event::Scalar(_, _, anchor, _)
            | Event::SequenceStart(anchor, _)
            | Event::MappingStart(anchor, _)
                if anchor != 0 =>
            {
                Err(ComposeError::Anchor)
            }
            Event::Scalar(_, _, _, Some(_))
            | Event::SequenceStart(_, Some(_))
            | Event::MappingStart(_, Some(_)) => Err(ComposeError::Tag),
            Event::Scalar(v, ..) => Ok(Node::Scalar(v)),
            Event::SequenceStart(..) => {
                let mut items = Vec::new();
                loop {
                    match self.next()? {
                        Event::SequenceEnd => return Ok(Node::Seq(items)),
                        ev => items.push(self.node(ev, depth + 1)?),
                    }
                }
            }
            Event::MappingStart(..) => {
                let mut entries: Vec<(String, Node)> = Vec::new();
                let mut seen = HashSet::new();
                loop {
                    let k = match self.next()? {
                        Event::MappingEnd => return Ok(Node::Map(entries)),
                        ev => match self.node(ev, depth + 1)? {
                            Node::Scalar(k) => k,
                            _ => return Err(ComposeError::NonScalarKey),
                        },
                    };
                    if k == "<<" {
                        return Err(ComposeError::MergeKey);
                    }
                    if !seen.insert(k.clone()) {
                        return Err(ComposeError::DuplicateKey(k));
                    }
                    let ev = self.next()?;
                    let v = self.node(ev, depth + 1)?;
                    entries.push((k, v));
                }
            }
            _ => Err(ComposeError::Syntax { line: 0, col: 0 }),
        }
    }

    /// Exactly one document.
    fn document(mut self) -> Result<Node, ComposeError> {
        if !matches!(self.next()?, Event::StreamStart) {
            return Err(ComposeError::Syntax { line: 0, col: 0 });
        }
        match self.next()? {
            Event::StreamEnd => return Err(ComposeError::Empty),
            Event::DocumentStart => {}
            _ => return Err(ComposeError::Syntax { line: 0, col: 0 }),
        }
        let ev = self.next()?;
        let root = self.node(ev, 0)?;
        if !matches!(self.next()?, Event::DocumentEnd) {
            return Err(ComposeError::Syntax { line: 0, col: 0 });
        }
        match self.next()? {
            Event::StreamEnd => Ok(root),
            _ => Err(ComposeError::MultipleDocuments),
        }
    }
}

fn parse(yaml: &str) -> Result<Node, ComposeError> {
    if yaml.len() > MAX_BYTES {
        return Err(ComposeError::TooLarge);
    }
    Loader {
        p: Parser::new_from_str(yaml),
        nodes: 0,
    }
    .document()
}

/// Lexical `..`/`.` resolution of `path` (absolute, or relative to `base`).
fn normalize(base: &str, path: &str) -> String {
    let joined = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("{base}/{path}")
    };
    let mut out: Vec<&str> = Vec::new();
    for c in joined.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    format!("/{}", out.join("/"))
}

struct Check {
    project: String,
    dir: String,
    /// Service and network names defined in this file.
    services: Vec<String>,
    networks: Vec<String>,
    service: Option<String>,
    findings: Vec<Finding>,
    errors: Vec<ComposeError>,
    host_paths: Vec<String>,
}

impl Check {
    fn find(&mut self, kind: FindingKind, key: &str, value: &str) {
        self.findings.push(Finding {
            service: self.service.clone(),
            kind,
            detail: format!("{key}: {value}"),
        });
    }

    fn shape(&mut self, path: &str) {
        self.errors.push(ComposeError::Shape(path.to_owned()));
    }

    fn under_project(&self, p: &str) -> bool {
        p == self.dir || p.starts_with(&format!("{}/", self.dir))
    }

    /// A host path Compose or the daemon will use; `kind` if it resolves
    /// outside the project directory (relative to `base`).
    fn host_path(&mut self, kind: FindingKind, key: &str, raw: &str, base: &str) {
        let raw = raw.trim();
        if raw.contains('$') {
            return self.find(FindingKind::Interpolated, key, raw);
        }
        if raw.starts_with('~') {
            return self.find(kind, key, raw);
        }
        let p = normalize(base, raw);
        // A bind of the project directory itself, its compose.yaml or .env
        // would let a container rewrite what the next deploy trusts.
        let own = kind == FindingKind::BindMount
            && (p == self.dir
                || p == format!("{}/compose.yaml", self.dir)
                || p == format!("{}/.env", self.dir));
        if own || !self.under_project(&p) {
            self.find(kind, key, raw);
        } else if !self.host_paths.contains(&p) {
            self.host_paths.push(p);
        }
    }

    fn host_mode(&mut self, key: &str, v: &Node) {
        match v.scalar() {
            Some(s) if s.contains('$') => self.find(FindingKind::Interpolated, key, s),
            Some(s) if s.trim().eq_ignore_ascii_case("host") => {
                self.find(FindingKind::HostNamespace, key, s)
            }
            Some(_) => {}
            None => self.shape(key),
        }
    }

    /// `pid`/`ipc`/`network_mode`: allow-listed values only.
    fn ns_mode(&mut self, key: &str, v: &Node) {
        if v.is_null() {
            return;
        }
        let Some(s) = v.scalar() else {
            return self.shape(key);
        };
        let t = s.trim();
        if t.contains('$') {
            return self.find(FindingKind::Interpolated, key, s);
        }
        let ok = matches!(t, "none" | "bridge" | "private" | "shareable")
            || t.strip_prefix("service:")
                .is_some_and(|n| self.services.iter().any(|x| x == n))
            || (key == "network_mode" && (t == "default" || self.networks.iter().any(|x| x == t)));
        if !ok {
            self.find(FindingKind::HostNamespace, key, s);
        }
    }

    /// `volumes_from`: only `service:<service in this file>[:ro|:rw]`.
    fn volumes_from(&mut self, key: &str, v: &Node) {
        let Some(items) = v.scalars() else {
            return self.shape(key);
        };
        for it in items {
            let t = it.trim();
            if t.contains('$') {
                self.find(FindingKind::Interpolated, key, it);
                continue;
            }
            let ok = t.strip_prefix("service:").is_some_and(|r| {
                let (name, mode) = r.split_once(':').unwrap_or((r, "ro"));
                matches!(mode, "ro" | "rw") && self.services.iter().any(|x| x == name)
            });
            if !ok {
                self.find(FindingKind::ForeignContainer, key, it);
            }
        }
    }

    /// `post_start`/`pre_stop`: privileged hooks or `$` in what they run.
    fn hooks(&mut self, key: &str, v: &Node) {
        let items = match v {
            Node::Seq(items) => items,
            _ if v.is_null() => return,
            _ => return self.shape(key),
        };
        for h in items {
            if !matches!(h, Node::Map(_)) {
                self.shape(key);
                continue;
            }
            if h.get("privileged").is_some_and(|p| !p.is_false()) {
                self.find(FindingKind::Privileged, &format!("{key}.privileged"), "…");
            }
            for sub in ["command", "environment"] {
                if h.get(sub).is_some_and(Node::has_dollar) {
                    self.find(FindingKind::Interpolated, &format!("{key}.{sub}"), "…");
                }
            }
        }
    }

    /// `build.cache_from`/`cache_to`: `type=local` reads/writes host paths.
    fn cache_entries(&mut self, key: &str, v: &Node, dir: &str) {
        let Some(entries) = v.scalars() else {
            return self.shape(key);
        };
        for e in entries {
            if e.contains('$') {
                self.find(FindingKind::Interpolated, key, e);
                continue;
            }
            let fields: Vec<(&str, &str)> = e
                .split(',')
                .filter_map(|f| f.split_once('='))
                .map(|(k, v)| (k.trim(), v.trim()))
                .collect();
            if !fields.iter().any(|&(k, v)| k == "type" && v == "local") {
                continue;
            }
            for (k, p) in fields {
                if matches!(k, "src" | "dest") {
                    self.host_path(FindingKind::HostFile, key, p, dir);
                }
            }
        }
    }

    /// `build.ssh`: a bare `default`/id uses the (absent) agent socket; an
    /// entry with a path reads a host key file.
    fn build_ssh(&mut self, v: &Node) {
        const KEY: &str = "build.ssh";
        match v {
            Node::Map(m) => {
                for (id, p) in m {
                    if !p.is_null() {
                        self.find(FindingKind::HostFile, KEY, id);
                    }
                }
            }
            _ => match v.scalars() {
                Some(entries) => {
                    for e in entries {
                        if e.contains('$') {
                            self.find(FindingKind::Interpolated, KEY, e);
                        } else if e.contains('=') {
                            self.find(FindingKind::HostFile, KEY, e);
                        }
                    }
                }
                None => self.shape(KEY),
            },
        }
    }

    fn service(&mut self, name: &str, svc: &Node) {
        self.service = Some(name.to_owned());
        let Node::Map(entries) = svc else {
            return self.shape(&format!("services.{name}"));
        };
        let dir = self.dir.clone();
        for (k, v) in entries {
            match k.as_str() {
                "privileged" if !v.is_false() => {
                    self.find(FindingKind::Privileged, k, v.scalar().unwrap_or("…"))
                }
                "cap_add" => match v.scalars() {
                    Some(caps) => {
                        for c in caps {
                            let n = c.trim().to_ascii_uppercase();
                            let n = n.strip_prefix("CAP_").unwrap_or(&n);
                            if c.contains('$') {
                                self.find(FindingKind::Interpolated, k, c);
                            } else if !CAP_ALLOW.contains(&n) {
                                self.find(FindingKind::CapAdd, k, c);
                            }
                        }
                    }
                    None => self.shape(k),
                },
                "pid" | "ipc" | "network_mode" => self.ns_mode(k, v),
                "userns_mode" | "cgroup" | "uts" => self.host_mode(k, v),
                "devices" | "device_cgroup_rules" | "gpus" if !v.is_empty() => {
                    self.find(FindingKind::Devices, k, "…")
                }
                "deploy" => {
                    let dev = v
                        .get("resources")
                        .and_then(|r| r.get("reservations"))
                        .and_then(|r| r.get("devices"));
                    if dev.is_some_and(|d| !d.is_empty()) {
                        self.find(
                            FindingKind::Devices,
                            "deploy.resources.reservations.devices",
                            "…",
                        );
                    }
                }
                "use_api_socket" if !v.is_literal_false() => {
                    self.find(FindingKind::DockerSocket, k, v.scalar().unwrap_or("…"))
                }
                "volumes_from" => self.volumes_from(k, v),
                "post_start" | "pre_stop" => self.hooks(k, v),
                "provider" | "cgroup_parent" if !v.is_empty() => {
                    self.find(FindingKind::Runtime, k, v.scalar().unwrap_or("…"))
                }
                "runtime" => match v.scalar() {
                    _ if v.is_null() => {}
                    Some(s) if s.contains('$') => self.find(FindingKind::Interpolated, k, s),
                    Some(s) if s.trim() == "runc" => {}
                    Some(s) => self.find(FindingKind::Runtime, k, s),
                    None => self.shape(k),
                },
                "security_opt" => match v.scalars() {
                    Some(opts) => {
                        for o in opts {
                            if !security_opt_ok(o) {
                                self.find(FindingKind::SecurityOpt, k, o);
                            }
                        }
                    }
                    None => self.shape(k),
                },
                "volumes" => match v {
                    Node::Seq(items) => {
                        for it in items {
                            self.volume(it);
                        }
                    }
                    _ if v.is_null() => {}
                    _ => self.shape(k),
                },
                "extends" => {
                    if v.get("file").is_some_and(|f| !f.is_null()) {
                        self.find(FindingKind::ExternalFile, "extends.file", "…");
                    }
                }
                "env_file" | "label_file" => self.files(k, v),
                "build" => self.build(v, &dir),
                _ => {}
            }
        }
    }

    /// `env_file`/`label_file`: a path, or a list of paths / `{path}` maps.
    fn files(&mut self, key: &str, v: &Node) {
        let items: Vec<&Node> = match v {
            Node::Seq(items) => items.iter().collect(),
            _ if v.is_null() => Vec::new(),
            _ => vec![v],
        };
        let dir = self.dir.clone();
        for it in items {
            match it
                .scalar()
                .or_else(|| it.get("path").and_then(Node::scalar))
            {
                Some(p) => self.host_path(FindingKind::HostFile, key, p, &dir),
                None => self.shape(key),
            }
        }
    }

    fn volume(&mut self, v: &Node) {
        let dir = self.dir.clone();
        match v {
            Node::Scalar(s) => {
                // `[source:]target[:mode]`; one part is an anonymous volume.
                let parts: Vec<&str> = s.split(':').collect();
                if parts.len() < 2 {
                    return;
                }
                let src = parts[0].trim();
                if src.contains('$') {
                    self.find(FindingKind::Interpolated, "volumes", s);
                } else if src.starts_with(['/', '.', '~']) {
                    self.host_path(FindingKind::BindMount, "volumes", src, &dir);
                }
                // Otherwise a named volume (its definition is checked at the
                // top level).
            }
            Node::Map(_) => {
                let ty = v.get("type").and_then(Node::scalar).unwrap_or("");
                let src = v.get("source").and_then(Node::scalar).unwrap_or("");
                if ty.contains('$') || src.contains('$') {
                    return self.find(FindingKind::Interpolated, "volumes", src);
                }
                match ty.trim() {
                    "bind" => self.host_path(FindingKind::BindMount, "volumes", src, &dir),
                    "" if src.starts_with(['/', '.', '~']) => {
                        self.host_path(FindingKind::BindMount, "volumes", src, &dir)
                    }
                    "" | "volume" | "tmpfs" | "image" => {}
                    other => self.find(FindingKind::BindMount, "volumes.type", other),
                }
            }
            Node::Seq(_) => self.shape("volumes"),
        }
    }

    fn build(&mut self, v: &Node, dir: &str) {
        let ctx = match v {
            Node::Scalar(s) => Some(s.as_str()),
            Node::Map(_) => match v.get("context") {
                None => None,
                Some(c) => match c.scalar() {
                    Some(s) => Some(s),
                    None => return self.shape("build.context"),
                },
            },
            Node::Seq(_) => return self.shape("build"),
        };
        let ctx = ctx.unwrap_or(".");
        let ctx_dir = if is_remote(ctx) {
            None
        } else {
            self.host_path(FindingKind::HostFile, "build.context", ctx, dir);
            Some(normalize(dir, ctx.trim()))
        };
        if let Node::Map(_) = v {
            if let (Some(df), Some(cd)) = (v.get("dockerfile").and_then(Node::scalar), &ctx_dir) {
                self.host_path(FindingKind::HostFile, "build.dockerfile", df, cd);
            }
            match v.get("additional_contexts") {
                Some(Node::Map(m)) => {
                    for (_, c) in m {
                        match c.scalar() {
                            Some(s) => self.extra_context(s, dir),
                            None => self.shape("build.additional_contexts"),
                        }
                    }
                }
                Some(Node::Seq(items)) => {
                    for it in items {
                        match it.scalar().and_then(|s| s.split_once('=')) {
                            Some((_, s)) => self.extra_context(s, dir),
                            None => self.shape("build.additional_contexts"),
                        }
                    }
                }
                Some(n) if !n.is_null() => self.shape("build.additional_contexts"),
                _ => {}
            }
            if v.get("privileged").is_some_and(|p| !p.is_false()) {
                self.find(FindingKind::Privileged, "build.privileged", "…");
            }
            if v.get("entitlements").is_some_and(|e| !e.is_empty()) {
                self.find(FindingKind::Privileged, "build.entitlements", "…");
            }
            if let Some(n) = v.get("network") {
                self.host_mode("build.network", n);
            }
            for key in ["cache_from", "cache_to"] {
                if let Some(n) = v.get(key) {
                    self.cache_entries(&format!("build.{key}"), n, dir);
                }
            }
            if let Some(n) = v.get("ssh") {
                self.build_ssh(n);
            }
        }
    }

    fn extra_context(&mut self, s: &str, dir: &str) {
        let s = s.trim();
        let path = s.strip_prefix("oci-layout://").unwrap_or(s);
        if path == s && (is_remote(s) || s.starts_with("service:") || s.starts_with("target:")) {
            return;
        }
        self.host_path(
            FindingKind::HostFile,
            "build.additional_contexts",
            path,
            dir,
        );
    }

    fn top_level(&mut self, root: &Node) {
        let Node::Map(entries) = root else {
            return self.shape("(document)");
        };
        let dir = self.dir.clone();
        let prefix = format!("{}_", self.project);
        let names = |key: &str| match root.get(key) {
            Some(Node::Map(m)) => m.iter().map(|(k, _)| k.clone()).collect(),
            _ => Vec::new(),
        };
        self.services = names("services");
        self.networks = names("networks");
        for (k, v) in entries {
            self.service = None;
            match k.as_str() {
                "services" => match v {
                    Node::Map(svcs) => {
                        for (name, svc) in svcs {
                            self.service(name, svc);
                        }
                    }
                    _ if v.is_null() => {}
                    _ => self.shape(k),
                },
                "include" if !v.is_null() => self.find(FindingKind::ExternalFile, k, "…"),
                "volumes" => self.each_def(k, v, |c, name, def| {
                    let dev = def.get("driver_opts").and_then(|o| o.get("device"));
                    if let Some(d) = dev {
                        match d.scalar() {
                            Some(p) => c.host_path(
                                FindingKind::BindMount,
                                &format!("volumes.{name}.driver_opts.device"),
                                p,
                                &dir,
                            ),
                            None => c.shape("volumes.driver_opts.device"),
                        }
                    }
                    let key = format!("volumes.{name}");
                    if def.get("external").is_some_and(|e| !e.is_literal_false()) {
                        c.find(FindingKind::ExternalVolume, &format!("{key}.external"), "…");
                    }
                    if let Some(n) = def.get("name") {
                        let s = n.scalar().unwrap_or("…");
                        if s.contains('$') {
                            c.find(FindingKind::Interpolated, &format!("{key}.name"), s);
                        } else if !s.trim().starts_with(&prefix) {
                            c.find(FindingKind::ExternalVolume, &format!("{key}.name"), s);
                        }
                    }
                }),
                "networks" => self.each_def(k, v, |c, name, def| {
                    let host = |key: &str| {
                        def.get(key)
                            .and_then(Node::scalar)
                            .is_some_and(|s| s.trim() == "host" || s.contains('$'))
                    };
                    if name == "host" || host("name") || host("driver") {
                        c.find(FindingKind::HostNetwork, "networks", name);
                    }
                }),
                "secrets" | "configs" => self.each_def(k, v, |c, name, def| {
                    if let Some(f) = def.get("file") {
                        match f.scalar() {
                            Some(p) => c.host_path(
                                FindingKind::HostFile,
                                &format!("{k}.{name}.file"),
                                p,
                                &dir,
                            ),
                            None => c.shape(k),
                        }
                    }
                }),
                _ => {}
            }
        }
    }

    /// Top-level definition maps (`volumes`, `networks`, `secrets`, …);
    /// entries may be null.
    fn each_def(&mut self, key: &str, v: &Node, mut f: impl FnMut(&mut Self, &str, &Node)) {
        match v {
            Node::Map(defs) => {
                for (name, def) in defs {
                    match def {
                        Node::Map(_) => f(self, name, def),
                        _ if def.is_null() => f(self, name, def),
                        _ => self.shape(&format!("{key}.{name}")),
                    }
                }
            }
            _ if v.is_null() => {}
            _ => self.shape(key),
        }
    }
}

fn is_remote(s: &str) -> bool {
    let s = s.trim();
    s.contains("://") || s.starts_with("git@")
}

fn security_opt_ok(o: &str) -> bool {
    matches!(
        o.trim(),
        "no-new-privileges"
            | "no-new-privileges:true"
            | "no-new-privileges=true"
            | "apparmor=docker-default"
            | "apparmor:docker-default"
    )
}

/// Parses and checks one Compose file for project `project` (bind mounts
/// may only reach below `/srv/<project>/`).
pub fn validate(project: &ComposeProject, yaml: &str) -> ComposeVerdict {
    let root = match parse(yaml) {
        Ok(r) => r,
        Err(e) => {
            return ComposeVerdict {
                ok: false,
                errors: vec![e],
                ..ComposeVerdict::default()
            };
        }
    };
    let mut c = Check {
        project: project.as_str().to_owned(),
        services: Vec::new(),
        networks: Vec::new(),
        dir: format!("/srv/{}", project.as_str()),
        service: None,
        findings: Vec::new(),
        errors: Vec::new(),
        host_paths: Vec::new(),
    };
    c.top_level(&root);
    ComposeVerdict {
        ok: c.errors.is_empty(),
        requires_elevated: c.findings,
        errors: c.errors,
        host_paths: c.host_paths,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn v(yaml: &str) -> ComposeVerdict {
        validate(&ComposeProject::new("app").unwrap(), yaml)
    }

    fn kinds(yaml: &str) -> Vec<FindingKind> {
        let r = v(yaml);
        assert!(r.ok, "{yaml}: {:?}", r.errors);
        r.requires_elevated.iter().map(|f| f.kind).collect()
    }

    fn error(yaml: &str) -> ComposeError {
        let r = v(yaml);
        assert!(!r.ok, "{yaml} should be refused");
        r.errors[0].clone()
    }

    fn svc(body: &str) -> String {
        format!("services:\n  web:\n    image: nginx\n{body}")
    }

    use FindingKind::*;

    #[test]
    fn plain_file_is_clean() {
        let yaml = "services:\n  web:\n    image: nginx:1.27\n    ports: [\"127.0.0.1:8080:80\"]\n    \
                    volumes:\n      - ./html:/usr/share/nginx/html:ro\n      - data:/data\n      \
                    - /srv/app/conf:/conf\n    cap_add: [NET_BIND_SERVICE, cap_chown]\n    \
                    security_opt: [\"no-new-privileges:true\"]\n    privileged: false\n    \
                    env_file: .env\n    build:\n      context: ./src\n      dockerfile: Dockerfile\n\
                    volumes:\n  data:\nnetworks:\n  default:\n";
        assert_eq!(kinds(yaml), vec![]);
        assert!(!v(yaml).escalates());
    }

    #[test]
    fn deny_list() {
        for (body, want) in [
            ("    privileged: true\n", Privileged),
            ("    privileged: \"yes\"\n", Privileged),
            ("    cap_add: [SYS_ADMIN]\n", CapAdd),
            ("    cap_add: [ALL]\n", CapAdd),
            ("    cap_add:\n      - CAP_SYS_PTRACE\n", CapAdd),
            ("    pid: host\n", HostNamespace),
            ("    ipc: \"host\"\n", HostNamespace),
            ("    network_mode: Host\n", HostNamespace),
            ("    userns_mode: host\n", HostNamespace),
            ("    cgroup: host\n", HostNamespace),
            ("    devices: [\"/dev/sda:/dev/sda\"]\n", Devices),
            ("    device_cgroup_rules: [\"b 8:* rmw\"]\n", Devices),
            ("    security_opt: [\"apparmor:unconfined\"]\n", SecurityOpt),
            ("    security_opt: [\"seccomp=unconfined\"]\n", SecurityOpt),
            ("    security_opt: [\"label=disable\"]\n", SecurityOpt),
            (
                "    security_opt: [\"systempaths=unconfined\"]\n",
                SecurityOpt,
            ),
            ("    volumes: [\"/:/host\"]\n", BindMount),
            (
                "    volumes: [\"/var/run/docker.sock:/var/run/docker.sock\"]\n",
                BindMount,
            ),
            ("    volumes: [\"../other:/x\"]\n", BindMount),
            ("    volumes: [\"./a/../../../etc:/x\"]\n", BindMount),
            ("    volumes: [\"~/.ssh:/x\"]\n", BindMount),
            ("    volumes: [\"/srv/app2:/x\"]\n", BindMount),
            ("    volumes: [\"${HOME}:/x\"]\n", Interpolated),
            (
                "    volumes:\n      - type: bind\n        source: /etc\n        target: /x\n",
                BindMount,
            ),
            (
                "    volumes:\n      - source: ../../etc\n        target: /x\n",
                BindMount,
            ),
            (
                "    volumes:\n      - type: npipe\n        source: x\n        target: /x\n",
                BindMount,
            ),
            ("    env_file: /etc/shadow\n", HostFile),
            ("    env_file:\n      - path: ../x.env\n", HostFile),
            ("    label_file: /etc/x\n", HostFile),
            ("    build: /\n", HostFile),
            (
                "    build:\n      context: .\n      dockerfile: ../../../etc/Dockerfile\n",
                HostFile,
            ),
            (
                "    build:\n      context: .\n      additional_contexts:\n        etc: /etc\n",
                HostFile,
            ),
            (
                "    build:\n      context: .\n      privileged: true\n",
                Privileged,
            ),
            (
                "    build:\n      context: .\n      network: host\n",
                HostNamespace,
            ),
            (
                "    extends:\n      file: ../other.yaml\n      service: web\n",
                ExternalFile,
            ),
            ("    network_mode: ${NM}\n", Interpolated),
            ("    privileged: ${P}\n", Privileged),
        ] {
            assert_eq!(kinds(&svc(body)), vec![want], "{body}");
        }
    }

    #[test]
    fn top_level_deny_list() {
        for (yaml, want) in [
            ("include:\n  - ../other/compose.yaml\n", ExternalFile),
            (
                "volumes:\n  v:\n    driver_opts:\n      type: none\n      o: bind\n      device: /etc\n",
                BindMount,
            ),
            ("networks:\n  host:\n    external: true\n", HostNetwork),
            (
                "networks:\n  n:\n    name: host\n    external: true\n",
                HostNetwork,
            ),
            ("secrets:\n  s:\n    file: /etc/shadow\n", HostFile),
            ("configs:\n  c:\n    file: ../../etc/passwd\n", HostFile),
        ] {
            assert_eq!(kinds(yaml), vec![want], "{yaml}");
        }
        // Inside the project: fine.
        assert_eq!(kinds("secrets:\n  s:\n    file: ./secret.txt\n"), vec![]);
        assert_eq!(kinds("services:\n  w:\n    extends: base\n"), vec![]);
        assert_eq!(
            kinds("services:\n  w:\n    build: https://github.com/x/y.git\n"),
            vec![]
        );
    }

    #[test]
    fn hardened_service_keys() {
        for (body, want) in [
            ("    use_api_socket: true\n", DockerSocket),
            ("    use_api_socket: ~\n", DockerSocket),
            ("    use_api_socket: \"no\"\n", DockerSocket),
            (
                "    post_start:\n      - command: [id]\n        privileged: true\n",
                Privileged,
            ),
            (
                "    pre_stop:\n      - command: [sh, -c, \"echo $X\"]\n",
                Interpolated,
            ),
            (
                "    post_start:\n      - command: id\n        environment: {A: $B}\n",
                Interpolated,
            ),
            ("    volumes_from: [\"container:db\"]\n", ForeignContainer),
            ("    volumes_from: [web]\n", ForeignContainer),
            ("    volumes_from: [\"service:ghost\"]\n", ForeignContainer),
            (
                "    volumes_from: [\"service:web:rwx\"]\n",
                ForeignContainer,
            ),
            ("    network_mode: \"container:db\"\n", HostNamespace),
            ("    network_mode: \"service:ghost\"\n", HostNamespace),
            ("    network_mode: undeclared\n", HostNamespace),
            ("    pid: \"container:x\"\n", HostNamespace),
            ("    ipc: \"service:ghost\"\n", HostNamespace),
            ("    uts: host\n", HostNamespace),
            ("    gpus: all\n", Devices),
            (
                "    deploy:\n      resources:\n        reservations:\n          devices:\n            - capabilities: [gpu]\n",
                Devices,
            ),
            ("    provider:\n      type: model\n", Runtime),
            ("    cgroup_parent: /system.slice\n", Runtime),
            ("    runtime: nvidia\n", Runtime),
            ("    runtime: ${R}\n", Interpolated),
            (
                "    build:\n      context: .\n      cache_from: [\"type=local,src=/var/cache\"]\n",
                HostFile,
            ),
            (
                "    build:\n      context: .\n      cache_to: [\"type=local,dest=../../tmp\"]\n",
                HostFile,
            ),
            (
                "    build:\n      context: .\n      ssh: [\"default=/root/.ssh/id_ed25519\"]\n",
                HostFile,
            ),
            (
                "    build:\n      context: .\n      ssh:\n        id: /root/.ssh/key\n",
                HostFile,
            ),
            ("    volumes: [\".:/x\"]\n", BindMount),
            ("    volumes: [\"/srv/app:/x\"]\n", BindMount),
            ("    volumes: [\"./compose.yaml:/x\"]\n", BindMount),
            ("    volumes: [\"./.env:/x:ro\"]\n", BindMount),
            (
                "    volumes:\n      - type: bind\n        source: ./x/..\n        target: /x\n",
                BindMount,
            ),
        ] {
            let yaml = format!(
                "services:\n  db:\n    image: x\n  web:\n    image: nginx\n{body}networks:\n  back:\n"
            );
            assert_eq!(kinds(&yaml), vec![want], "{body}");
        }
        // Allowed values.
        for body in [
            "    use_api_socket: false\n",
            "    volumes_from: [\"service:db\", \"service:db:ro\"]\n",
            "    network_mode: \"service:db\"\n",
            "    network_mode: none\n",
            "    network_mode: bridge\n",
            "    network_mode: back\n",
            "    pid: \"service:db\"\n",
            "    ipc: shareable\n",
            "    ipc: private\n",
            "    runtime: runc\n",
            "    post_start:\n      - command: [\"/bin/init\"]\n        privileged: false\n",
            "    build:\n      context: .\n      cache_from: [\"type=local,src=./cache\", \"type=registry,ref=x/y\"]\n      cache_to: [\"type=inline\"]\n      ssh: [default]\n",
            "    volumes: [\"./data:/x\"]\n",
        ] {
            let yaml = format!(
                "services:\n  db:\n    image: x\n  web:\n    image: nginx\n{body}networks:\n  back:\n"
            );
            assert_eq!(kinds(&yaml), vec![], "{body}");
        }
    }

    #[test]
    fn top_level_volumes() {
        for (yaml, want) in [
            ("volumes:\n  v:\n    external: true\n", vec![ExternalVolume]),
            ("volumes:\n  v:\n    external: ~\n", vec![ExternalVolume]),
            (
                "volumes:\n  v:\n    name: other_data\n",
                vec![ExternalVolume],
            ),
            ("volumes:\n  v:\n    name: app\n", vec![ExternalVolume]),
            (
                "volumes:\n  v:\n    external: true\n    name: app_x\n",
                vec![ExternalVolume],
            ),
            ("volumes:\n  v:\n    name: ${N}\n", vec![Interpolated]),
            (
                "volumes:\n  v:\n    external: false\n    name: app_data\n",
                vec![],
            ),
            ("volumes:\n  v:\n", vec![]),
        ] {
            assert_eq!(kinds(yaml), want, "{yaml}");
        }
    }

    #[test]
    fn findings_name_the_service() {
        let r = v("services:\n  a:\n    image: x\n  b:\n    privileged: true\n");
        assert_eq!(r.requires_elevated[0].service.as_deref(), Some("b"));
        assert!(r.escalates());
    }

    #[test]
    fn structural_tricks_are_errors() {
        use ComposeError::*;
        let laughs = "a: &a [x, x]\nb: &b [*a, *a]\nc: [*b, *b]\n";
        assert_eq!(error(laughs), Anchor);
        assert!(matches!(error("x: *a\n"), Syntax { .. } | Alias));
        assert_eq!(error("a: &x 1\n"), Anchor);
        assert_eq!(
            error("services:\n  web:\n    <<: {privileged: true}\n"),
            MergeKey
        );
        assert_eq!(
            error("services:\n  web:\n    \"<<\": {privileged: true}\n"),
            MergeKey
        );
        assert_eq!(
            error("services:\n  web:\n    privileged: false\n    privileged: true\n"),
            DuplicateKey("privileged".into())
        );
        assert_eq!(error("services: !!map\n  web: {}\n"), Tag);
        assert_eq!(
            error("services:\n  web:\n    privileged: !!bool true\n"),
            Tag
        );
        assert_eq!(error("? [a]\n: b\n"), NonScalarKey);
        assert_eq!(
            error("a: 1\n---\nservices: {w: {privileged: true}}\n"),
            MultipleDocuments
        );
        assert_eq!(error(""), Empty);
        assert_eq!(error("services: [a]\n"), Shape("services".into()));
        assert_eq!(error("- a\n"), Shape("(document)".into()));
        let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));
        assert_eq!(error(&format!("a: {deep}\n")), TooDeep);
        let big = format!("x: \"{}\"\n", "a".repeat(MAX_BYTES));
        assert_eq!(error(&big), TooLarge);
    }

    #[test]
    fn alias_without_anchor_def_and_flow_nesting_bomb() {
        // Unbounded flow nesting stops at the scanner's own limit or ours.
        let r = v(&"[".repeat(100_000));
        assert!(!r.ok);
    }

    #[test]
    fn normalize_paths() {
        assert_eq!(normalize("/srv/app", "./x/../y"), "/srv/app/y");
        assert_eq!(normalize("/srv/app", "../../../../etc"), "/etc");
        assert_eq!(normalize("/srv/app", "/a//b/./c"), "/a/b/c");
        assert_eq!(normalize("/srv/app", "."), "/srv/app");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Arbitrary input never panics, and a refused file never reports
        /// findings.
        #[test]
        fn never_panics(s in "[ -~\\n\\t]{0,300}") {
            let r = v(&s);
            prop_assert!(r.ok || r.requires_elevated.is_empty());
            prop_assert_eq!(r.ok, r.errors.is_empty());
        }

        /// YAML-ish noise built from the tricky tokens.
        #[test]
        fn yaml_token_soup(parts in prop::collection::vec(prop::sample::select(vec![
            "services:", "\n", "  ", "web:", "privileged: true", "&a ", "*a", "<<: ", "!!str ",
            "[", "]", "{", "}", ",", "- ", "? ", ": ", "\"", "'", "---\n", "volumes:", "/etc:/x",
            "#", "|\n", ">\n", "~", "null",
        ]), 0..60)) {
            let s: String = parts.concat();
            let r = v(&s);
            prop_assert_eq!(r.ok, r.errors.is_empty());
            prop_assert!(r.ok || r.requires_elevated.is_empty());
        }

        /// Any service privileged key with a truthy value escalates, however
        /// it's quoted.
        #[test]
        fn privileged_any_quoting(q in prop::sample::select(vec!["", "'", "\""]),
                                  val in prop::sample::select(vec!["true", "True", "yes", "on", "1", "y"])) {
            let r = v(&format!("services:\n  w:\n    privileged: {q}{val}{q}\n"));
            prop_assert!(r.escalates());
        }

        /// Bind sources outside the project always escalate.
        #[test]
        fn bind_outside(dir in "(etc|root|var|srv/other|home/[a-z]{1,6})",
                        rel in prop::bool::ANY) {
            let src = if rel { format!("../../../{dir}") } else { format!("/{dir}") };
            let r = v(&format!("services:\n  w:\n    volumes: [\"{src}:/x\"]\n"));
            prop_assert!(r.escalates(), "{}", src);
        }
    }
}
