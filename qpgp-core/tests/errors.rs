use qpgp_core::QpgpError;

#[test]
fn error_display_messages() {
    let err = QpgpError::not_implemented("feature");
    assert_eq!(err.to_string(), "not implemented: feature");

    let err = QpgpError::InvalidInput("bad input".into());
    assert_eq!(err.to_string(), "invalid input: bad input");

    let err = QpgpError::Backend("oops".into());
    assert_eq!(err.to_string(), "backend error: oops");

    let err = QpgpError::Io("disk".into());
    assert_eq!(err.to_string(), "io error: disk");
}
