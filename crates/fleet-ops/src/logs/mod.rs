//! `logs` group handlers (design §4.6): journald query/follow and
//! allow-listed log file tails. Everything read is untrusted server data:
//! it is size-capped, decoded lossily and never interpreted.

pub mod journal;
pub mod lines;
pub mod logfile;
pub mod logfiles;
pub mod weblog;

pub use journal::JournalHandler;
pub use lines::{FakeLineSpawner, LineSource, LineSpawner, SystemLineSpawner};
pub use logfile::LogfileTailHandler;
pub use logfiles::LogfilesListHandler;
pub use weblog::WeblogHandler;

use crate::handler::Registry;
use fleet_proto::op::tag;
use std::rc::Rc;

/// Registers the stateless `logs` handlers with production spawners.
pub fn register(r: &mut Registry) {
    let journal = Rc::new(JournalHandler::new(Rc::new(SystemLineSpawner)));
    r.register(tag::JOURNAL_QUERY, journal.clone());
    r.register(tag::JOURNAL_FOLLOW, journal);
    r.register(tag::LOGFILE_TAIL, Rc::new(LogfileTailHandler::default()));
    r.register(tag::LOGFILES_LIST, Rc::new(LogfilesListHandler));
    r.register(tag::WEBLOG_QUERY, Rc::new(WeblogHandler::default()));
}
