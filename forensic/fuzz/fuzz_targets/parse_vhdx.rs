#![no_main]
use libfuzzer_sys::fuzz_target;
use vhdx_forensic::VhdxIntegrity;

fuzz_target!(|data: &[u8]| {
    // Must not panic on any input.
    let _ = VhdxIntegrity::new(data).analyse();
    // Ghost data check is also an opt-in path that must be panic-free.
    let _ = VhdxIntegrity::new(data).check_bat_ghost_data();
});
