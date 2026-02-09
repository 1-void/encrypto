use qpgp_core::{PqcLevel, PqcPolicy};

#[test]
fn defaults_are_strict() {
    assert_eq!(PqcPolicy::default(), PqcPolicy::Required);
    assert_eq!(PqcLevel::default(), PqcLevel::Baseline);
}
