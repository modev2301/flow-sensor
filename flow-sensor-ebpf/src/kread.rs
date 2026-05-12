//! Unaligned kernel-memory reads at byte offsets (BPF `bpf_probe_read_kernel`).

use aya_ebpf::helpers::bpf_probe_read_kernel_buf;

#[inline]
pub unsafe fn read_u8(ptr: *const u8) -> Result<u8, i64> {
    let mut b = [0u8; 1];
    bpf_probe_read_kernel_buf(ptr, &mut b).map_err(|e| e as i64)?;
    Ok(b[0])
}

#[inline]
pub unsafe fn read_u16_ne(ptr: *const u8) -> Result<u16, i64> {
    let mut b = [0u8; 2];
    bpf_probe_read_kernel_buf(ptr, &mut b).map_err(|e| e as i64)?;
    Ok(u16::from_ne_bytes(b))
}

#[inline]
pub unsafe fn read_u32_ne(ptr: *const u8) -> Result<u32, i64> {
    let mut b = [0u8; 4];
    bpf_probe_read_kernel_buf(ptr, &mut b).map_err(|e| e as i64)?;
    Ok(u32::from_ne_bytes(b))
}
