//! Causal chain tracking — links flows that are causally related.
//! When process A handles a request and calls process B, both flows share a chain_id.
//! This is the eBPF primitive that enables distributed tracing without instrumentation.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::kprobe,
    programs::ProbeContext,
};

use crate::{kread, maps::*};

/// Fires on clone/fork — child inherits parent's causal chain
#[kprobe(function = "wake_up_new_task")]
pub fn on_new_task(ctx: ProbeContext) -> u32 {
    match unsafe { handle_new_task(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_new_task(ctx: &ProbeContext) -> Result<u32, i64> {
    let parent_pid_tgid = bpf_get_current_pid_tgid();

    // Get parent's causal context
    let parent_ctx = match CAUSAL_MAP.get(&parent_pid_tgid) {
        Some(c) => *c,
        None => {
            // Parent has no chain — create one
            CausalCtx {
                chain_id: bpf_ktime_get_ns(),
                parent_chain_id: 0,
                depth: 0,
                origin_pid: (parent_pid_tgid >> 32) as u32,
                origin_ts_ns: bpf_ktime_get_ns(),
            }
        }
    };

    // Child task pointer is arg0
    let child_task = ctx.arg::<*const u8>(0).ok_or(-1)?;

    // Read child pid from task_struct
    // Offset of pid in task_struct (stable across 5.8-6.x)
    const TASK_PID_OFFSET: usize = 0x560;
    let child_pid = kread::read_u32_ne(child_task.add(TASK_PID_OFFSET)).unwrap_or(0);

    let child_pid_tgid = (child_pid as u64) << 32 | child_pid as u64;

    // Child inherits parent chain, increments depth
    let child_ctx = CausalCtx {
        chain_id: parent_ctx.chain_id,
        parent_chain_id: parent_ctx.chain_id,
        depth: parent_ctx.depth + 1,
        origin_pid: parent_ctx.origin_pid,
        origin_ts_ns: parent_ctx.origin_ts_ns,
    };

    let _ = CAUSAL_MAP.insert(&child_pid_tgid, &child_ctx, 0);
    Ok(0)
}

/// Clean up causal context when process exits
#[kprobe(function = "do_exit")]
pub fn on_exit(_ctx: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = CAUSAL_MAP.remove(&pid_tgid);
    0
}
