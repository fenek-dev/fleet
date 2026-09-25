//! Role add-ons (design §9.6). The manifests (`profiles/roles/*.toml`)
//! declare packages, the apt repository and its pinned key fingerprint,
//! ports (firewall module), sysctl overrides (sysctl module), kernel
//! modules to load (kernel.modules) and exceptions; these modules install
//! and configure the software itself.

use crate::module::{Action, Change, Cmd, Ctx, Module, Status, file_change, read_file};
use crate::modules::{enable_change, install_change, systemctl};
use crate::profile::{AptRepo, Resolved, RoleManifest};
use fleet_ops::handler::OpError;
use fleet_proto::ErrorCode;
use fleet_proto::op::ProfileRole;

pub const KEYRINGS: &str = "/etc/apt/keyrings";
pub const SOURCES_DIR: &str = "/etc/apt/sources.list.d";
pub const PREFERENCES_DIR: &str = "/etc/apt/preferences.d";

pub fn key_path(r: &AptRepo) -> String {
    format!("{KEYRINGS}/fleet-{}.asc", r.name)
}
pub fn sources_path(r: &AptRepo) -> String {
    format!("{SOURCES_DIR}/fleet-{}.sources", r.name)
}
pub fn pin_path(r: &AptRepo) -> String {
    format!("{PREFERENCES_DIR}/fleet-{}", r.name)
}

fn os_id(ctx: &Ctx) -> Result<&str, OpError> {
    match ctx.facts.os.id.as_str() {
        id @ ("debian" | "ubuntu") => Ok(id),
        other => Err(OpError::new(ErrorCode::Unsupported).with_detail(format!("os {other:?}"))),
    }
}

pub fn sources(r: &AptRepo, os: &str, codename: &str) -> String {
    format!(
        "# Managed by Fleet (design §9.6).\n\
         Types: deb\n\
         URIs: {}\n\
         Suites: {}\n\
         Components: {}\n\
         Signed-By: {}\n",
        r.uri.replace("{os}", os),
        r.suite.as_deref().unwrap_or(codename),
        r.components.join(" "),
        key_path(r)
    )
}

/// Pinned to one major version: matching versions preferred, every other
/// version of these packages never installed.
pub fn pin(r: &AptRepo) -> Option<String> {
    let v = r.pin_version.as_ref()?;
    let pkgs = r.pin_packages.join(" ");
    Some(format!(
        "# Managed by Fleet (design §9.6).\n\
         Package: {pkgs}\n\
         Pin: version {v}\n\
         Pin-Priority: 990\n\
         \n\
         Package: {pkgs}\n\
         Pin: version *\n\
         Pin-Priority: -1\n"
    ))
}

/// Key (fetched, fingerprint-checked), sources and pin of `r`.
pub fn repo_plan(ctx: &Ctx, module: &'static str, r: &AptRepo) -> Result<Vec<Change>, OpError> {
    let os = os_id(ctx)?;
    let codename = ctx.facts.os.codename.as_str();
    if codename.is_empty() || !codename.bytes().all(|b| b.is_ascii_lowercase()) {
        return Err(OpError::new(ErrorCode::Unsupported).with_detail("no OS codename"));
    }
    let mut plan = Vec::new();
    let key = key_path(r);
    if read_file(&ctx.sys, &key)?.is_none() {
        plan.extend(install_change(
            ctx,
            module,
            &[
                "ca-certificates".to_owned(),
                "curl".to_owned(),
                "gnupg".to_owned(),
            ],
        ));
        let url = r.key_url.replace("{os}", os);
        plan.push(Change {
            module,
            description: format!("add the {} apt key (fingerprint {})", r.name, r.fingerprint),
            diff: format!("+ {key} from {url}\n"),
            actions: vec![Action::FetchKey {
                url,
                fingerprint: r.fingerprint.clone(),
                dest: key,
            }],
        });
    }
    plan.extend(file_change(
        &ctx.sys,
        module,
        &sources_path(r),
        &sources(r, os, codename),
        0o644,
    )?);
    if let Some(p) = pin(r) {
        plan.extend(file_change(&ctx.sys, module, &pin_path(r), &p, 0o644)?);
    }
    Ok(plan)
}

fn repo_paths(m: Option<&RoleManifest>) -> Vec<String> {
    m.and_then(|m| m.apt_repo.as_ref())
        .map(|r| vec![key_path(r), sources_path(r), pin_path(r)])
        .unwrap_or_default()
}

fn manifest(ctx: &Ctx, r: ProfileRole) -> Result<&RoleManifest, OpError> {
    ctx.profile
        .role(r)
        .ok_or_else(|| OpError::internal("role manifest missing"))
}

// ---- docker ----

pub const DAEMON_JSON: &str = "/etc/docker/daemon.json";
/// Exactly as design §9.6.
pub const DAEMON_JSON_TEXT: &str = "{\"log-driver\":\"local\",\"log-opts\":{\"max-size\":\"20m\",\"max-file\":\"5\"},\"live-restore\":true,\"no-new-privileges\":true,\"icc\":false,\"userland-proxy\":false,\"ip\":\"127.0.0.1\"}\n";

pub struct Docker;

impl Module for Docker {
    fn id(&self) -> &'static str {
        "role.docker"
    }
    fn title(&self) -> &'static str {
        "Docker Engine (official repository, pinned major) with a hardened daemon.json"
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let m = manifest(ctx, ProfileRole::Docker)?;
        let mut plan = match &m.apt_repo {
            Some(r) => repo_plan(ctx, self.id(), r)?,
            None => Vec::new(),
        };
        plan.extend(install_change(ctx, self.id(), &m.packages));
        if let Some(mut c) = file_change(&ctx.sys, self.id(), DAEMON_JSON, DAEMON_JSON_TEXT, 0o644)?
        {
            let restart = systemctl(["restart", "--", "docker.service"]);
            c.diff.push_str(&format!("$ {}\n", restart.display()));
            c.actions.push(Action::Run(restart));
            plan.push(c);
        }
        plan.extend(enable_change(ctx, self.id(), "docker.service"));
        Ok(plan)
    }

    fn paths(&self, p: &Resolved) -> Vec<String> {
        let mut v = repo_paths(p.role(ProfileRole::Docker));
        v.push(DAEMON_JSON.into());
        v
    }
}

// ---- web ----

pub const CADDYFILE: &str = "/etc/caddy/Caddyfile";
pub const CADDY_SNIPPETS: &str = "/etc/caddy/fleet-headers.caddy";
pub const CADDY_SITES_README: &str = "/etc/caddy/sites/README";
pub const CADDY: &str = "/usr/bin/caddy";
pub const NGINX: &str = "/usr/sbin/nginx";
pub const NGINX_CONF: &str = "/etc/nginx/conf.d/10-fleet-hardening.conf";

pub const CADDYFILE_TEXT: &str = "# Managed by Fleet (design §9.6). Sites: /etc/caddy/sites/*.caddy,\n\
# each importing fleet_headers (and fleet_tls where TLS is configured).\n\
{\n\
\tservers {\n\
\t\tprotocols h1 h2 h3\n\
\t}\n\
}\n\
\n\
import /etc/caddy/fleet-headers.caddy\n\
import /etc/caddy/sites/*.caddy\n";

pub fn caddy_snippets(max_body: &str) -> String {
    format!(
        "# Managed by Fleet (design §9.6).\n\
         (fleet_headers) {{\n\
         \theader {{\n\
         \t\tStrict-Transport-Security \"max-age=31536000\"\n\
         \t\tX-Content-Type-Options \"nosniff\"\n\
         \t\tReferrer-Policy \"strict-origin-when-cross-origin\"\n\
         \t\tContent-Security-Policy \"frame-ancestors 'self'\"\n\
         \t\tPermissions-Policy \"camera=(), microphone=(), geolocation=()\"\n\
         \t\t-Server\n\
         \t}}\n\
         \trequest_body {{\n\
         \t\tmax_size {max_body}\n\
         \t}}\n\
         }}\n\
         \n\
         (fleet_tls) {{\n\
         \ttls {{\n\
         \t\tprotocols tls1.2 tls1.3\n\
         \t}}\n\
         }}\n"
    )
}

pub fn nginx_conf(max_body: &str, rate: &str) -> String {
    format!(
        "# Managed by Fleet (design §9.6). Sites add `limit_req zone=fleet_req burst=40;`.\n\
         server_tokens off;\n\
         ssl_protocols TLSv1.2 TLSv1.3;\n\
         ssl_prefer_server_ciphers off;\n\
         ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;\n\
         ssl_session_tickets off;\n\
         client_max_body_size {max_body};\n\
         client_body_timeout 15s;\n\
         client_header_timeout 15s;\n\
         keepalive_timeout 30s;\n\
         send_timeout 30s;\n\
         limit_req_zone $binary_remote_addr zone=fleet_req:10m rate={rate};\n\
         add_header Strict-Transport-Security \"max-age=31536000\" always;\n\
         add_header X-Content-Type-Options \"nosniff\" always;\n\
         add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n\
         add_header Content-Security-Policy \"frame-ancestors 'self'\" always;\n\
         add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;\n\
         log_format fleet_json escape=json '{{\"time\":\"$time_iso8601\",\"remote\":\"$remote_addr\",\"host\":\"$host\",\"method\":\"$request_method\",\"uri\":\"$request_uri\",\"status\":$status,\"bytes\":$body_bytes_sent,\"agent\":\"$http_user_agent\",\"rt\":$request_time}}';\n\
         access_log /var/log/nginx/access.json fleet_json;\n"
    )
}

/// Manifest settings interpolated into config: `[0-9A-Za-z/]` only.
fn setting<'a>(m: &'a RoleManifest, key: &str, default: &'a str) -> Result<&'a str, OpError> {
    let v = m.settings.get(key).map_or(default, String::as_str);
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'/') {
        return Err(OpError::internal(format!("role setting {key}")));
    }
    Ok(v)
}

pub struct Web;

impl Web {
    fn caddy(m: &RoleManifest) -> bool {
        m.settings.get("server").is_none_or(|s| s == "caddy")
    }
}

impl Module for Web {
    fn id(&self) -> &'static str {
        "role.web"
    }
    fn title(&self) -> &'static str {
        "Web server with modern TLS and security headers"
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let m = manifest(ctx, ProfileRole::Web)?;
        let body = setting(m, "max_body", "16m")?;
        let id = self.id();
        let sys = &ctx.sys;
        let mut plan = Vec::new();
        let (unit, mut files, validate) = if Self::caddy(m) {
            if let Some(r) = &m.apt_repo {
                plan.extend(repo_plan(ctx, id, r)?);
            }
            plan.extend(install_change(ctx, id, &["caddy".to_owned()]));
            let mut f = Vec::new();
            f.extend(file_change(
                sys,
                id,
                CADDY_SNIPPETS,
                &caddy_snippets(&body.to_uppercase().replace('M', "MB")),
                0o644,
            )?);
            f.extend(file_change(
                sys,
                id,
                CADDY_SITES_README,
                "Fleet: one <site>.caddy per site, imported by /etc/caddy/Caddyfile.\n",
                0o644,
            )?);
            f.extend(file_change(sys, id, CADDYFILE, CADDYFILE_TEXT, 0o644)?);
            let v = Cmd::new(
                CADDY,
                ["validate", "--config", CADDYFILE, "--adapter", "caddyfile"],
            );
            ("caddy.service", f, v)
        } else {
            plan.extend(install_change(ctx, id, &["nginx".to_owned()]));
            let rate = setting(m, "rate", "20r/s")?;
            let f: Vec<Change> = file_change(sys, id, NGINX_CONF, &nginx_conf(body, rate), 0o644)?
                .into_iter()
                .collect();
            ("nginx.service", f, Cmd::new(NGINX, ["-t", "-q"]))
        };
        crate::module::then_run(
            &mut files,
            [
                Action::Validate(validate),
                Action::Run(systemctl(["try-reload-or-restart", "--", unit])),
            ],
        );
        plan.extend(files);
        plan.extend(enable_change(ctx, id, unit));
        Ok(plan)
    }

    fn paths(&self, p: &Resolved) -> Vec<String> {
        let mut v = repo_paths(p.role(ProfileRole::Web));
        v.extend([CADDYFILE, CADDY_SNIPPETS, CADDY_SITES_README, NGINX_CONF].map(String::from));
        v
    }
}

// ---- game (base) ----

/// Host tuning only (sysctl via the manifest); per-game templates come
/// later (design §15). Present so the role shows in the audit.
pub struct Game;

impl Module for Game {
    fn id(&self) -> &'static str {
        "role.game"
    }
    fn title(&self) -> &'static str {
        "Game server host tuning"
    }
    fn weight(&self) -> u8 {
        1
    }

    fn check(&self, ctx: &Ctx) -> Result<Status, OpError> {
        manifest(ctx, ProfileRole::Game)?;
        Ok(Status::Compliant)
    }

    fn plan(&self, _ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        Ok(Vec::new())
    }
}
