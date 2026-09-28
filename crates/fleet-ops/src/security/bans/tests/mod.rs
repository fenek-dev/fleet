mod config;
mod engine;
mod service;
mod web;

use super::*;
use crate::security::VecSink;
use crate::testutil::{T0, ctx_at};
use crate::{FakeRunner, SysCtx};
use std::rc::Rc;

pub(super) const MIN: u64 = 60_000;

pub(super) fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

pub(super) fn cidr(s: &str) -> Cidr {
    let (a, p) = s.split_once('/').unwrap();
    Cidr::new(ip(a), p.parse().unwrap()).unwrap()
}

pub(super) fn a(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

/// A service on a fake runner; the tempdir must outlive the context.
pub(super) fn service(
    cfg: BanConfig,
) -> (
    Rc<BanService>,
    Rc<FakeRunner>,
    Rc<VecSink>,
    SysCtx,
    tempfile::TempDir,
) {
    let runner = Rc::new(FakeRunner::new());
    let sink = Rc::new(VecSink::default());
    let dir = tempfile::tempdir().unwrap();
    let c = ctx_at(dir.path(), runner.clone(), T0);
    (BanService::new(cfg, sink.clone()), runner, sink, c, dir)
}

/// Like [`service`], but with an explicit write gate (design §5.4): lets a
/// test simulate the gate flipping between a decision and the write it
/// guards.
pub(super) fn service_with_gate(
    cfg: BanConfig,
    gate: Rc<dyn Fn() -> bool>,
) -> (
    Rc<BanService>,
    Rc<FakeRunner>,
    Rc<VecSink>,
    SysCtx,
    tempfile::TempDir,
) {
    let runner = Rc::new(FakeRunner::new());
    let sink = Rc::new(VecSink::default());
    let dir = tempfile::tempdir().unwrap();
    let c = ctx_at(dir.path(), runner.clone(), T0);
    (
        BanService::with_gate(cfg, sink.clone(), gate),
        runner,
        sink,
        c,
        dir,
    )
}
