//! [`BansHandler`]: `bans.list/add/remove`, `bans.config.get/set`.

use super::nft::run_nft;
use super::{BanService, MAX_MANUAL_S, ban_key, unban_args, validate_exempt};
use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput};
use crate::nftlock;
use fleet_proto::payload::BanReason;
use fleet_proto::{ErrorCode, Event, Op, Payload};
use std::rc::Rc;

/// `bans.list`, `bans.add`, `bans.remove`, `bans.config.get/set`.
pub struct BansHandler(pub Rc<BanService>);

impl OpHandler for BansHandler {
    fn validate(&self, _ctx: &SysCtx, op: &Op, meta: &OpMeta) -> Result<(), OpError> {
        match op {
            Op::BansList | Op::BansConfigGet | Op::BansRemove { .. } => Ok(()),
            Op::BansAdd {
                addr, duration_s, ..
            } => {
                let e = self.0.engine.borrow();
                if !(60..=MAX_MANUAL_S).contains(duration_s) || e.is_exempt(*addr, meta.now_ms) {
                    return Err(ErrorCode::InvalidArgument.into());
                }
                Ok(())
            }
            Op::BansConfigSet(c) => {
                c.validate()
                    .map_err(|e| OpError::from(ErrorCode::from(e)))?;
                validate_exempt(&c.exempt).map_err(Into::into)
            }
            _ => Err(ErrorCode::Unsupported.into()),
        }
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            let now = meta.now_ms;
            let svc = &self.0;
            match op {
                Op::BansList => {}
                Op::BansAdd {
                    addr, duration_s, ..
                } => {
                    let d = svc.engine.borrow_mut().manual(*addr, *duration_s, now)?;
                    svc.apply(ctx, d).await?;
                }
                Op::BansRemove { addr } => {
                    let key = ban_key(*addr);
                    let known = svc.engine.borrow_mut().remove(*addr);
                    let nft = {
                        let _table = nftlock::lock().await;
                        run_nft(ctx, unban_args(&key)).await
                    };
                    if known.is_none() && nft.is_err() {
                        return Err(ErrorCode::NotFound.into());
                    }
                    svc.sink.emit(Event::BanChanged {
                        addr: key.addr,
                        banned: false,
                        until_ms: None,
                        reason: known.map_or(BanReason::Manual, |b| b.reason),
                    });
                }
                Op::BansConfigGet => {
                    return Ok(OpOutput::Payload(Payload::BanConfig(
                        svc.engine.borrow().config().clone(),
                    )));
                }
                Op::BansConfigSet(c) => {
                    svc.set_config(ctx, c.clone(), now).await?;
                    return Ok(OpOutput::Payload(Payload::BanConfig(c.clone())));
                }
                _ => return Err(ErrorCode::Unsupported.into()),
            }
            Ok(OpOutput::Payload(Payload::Bans(svc.snapshot(now))))
        })
    }
}
