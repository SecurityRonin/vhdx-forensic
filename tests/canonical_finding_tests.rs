//! vhdx-forensic anomalies normalize onto the canonical `forensicnomicon::report`
//! model via the `Observation` producer trait (4-level -> 5-level re-grade).

use forensicnomicon::report::{Observation, Severity, Source};
use vhdx_forensic::VhdxIntegrityAnomaly;

#[test]
fn anomaly_converts_to_a_canonical_finding() {
    let a = VhdxIntegrityAnomaly::BothHeaderCopiesInvalid;
    let f = a.to_finding(Source {
        analyzer: "vhdx-forensic".to_string(),
        scope: "VHDX".to_string(),
        version: None,
    });
    assert_eq!(f.code, "VHDX-BOTH-HEADER-COPIES-INVALID");
    assert_eq!(f.severity, Some(Severity::Critical));
}
