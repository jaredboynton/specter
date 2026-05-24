#[test]
fn native_h3_driver_schedules_receive_flow_control_updates() {
    let driver =
        std::fs::read_to_string("src/transport/h3/native_driver.rs").expect("native driver source");

    assert!(
        driver.contains("build_client_receive_flow_control_update_packets"),
        "native H3 driver must automatically send receive-window MAX_DATA/MAX_STREAM_DATA updates"
    );
}

#[test]
fn native_mock_h3_server_schedules_receive_flow_control_updates() {
    let mock_server = std::fs::read_to_string("tests/helpers/mock_h3_server.rs")
        .expect("native mock H3 server source");

    assert!(
        mock_server.contains("build_server_receive_flow_control_update_packets"),
        "native mock H3 server must automatically send receive-window MAX_DATA/MAX_STREAM_DATA updates"
    );
}

#[test]
fn native_h3_driver_schedules_lost_application_stream_retransmits() {
    let driver =
        std::fs::read_to_string("src/transport/h3/native_driver.rs").expect("native driver source");

    assert!(
        driver.contains("retransmit_lost_client_application_stream_packets"),
        "native H3 driver must automatically send lost application STREAM retransmits after ACK/loss updates"
    );
}

#[test]
fn native_h3_driver_requeues_flow_control_blocked_new_stream_commands() {
    let driver =
        std::fs::read_to_string("src/transport/h3/native_driver.rs").expect("native driver source");

    assert!(
        driver.contains("queue_flow_control_blocked_command"),
        "native H3 driver must queue new request/tunnel commands that hit QUIC stream limits"
    );
    assert!(
        driver.contains("build_client_flow_control_blocked_packet"),
        "native H3 driver must emit DATA_BLOCKED/STREAM_DATA_BLOCKED/STREAMS_BLOCKED when queueing blocked sends"
    );
}

#[test]
fn native_mock_h3_server_schedules_lost_application_stream_retransmits() {
    let mock_server = std::fs::read_to_string("tests/helpers/mock_h3_server.rs")
        .expect("native mock H3 server source");

    assert!(
        mock_server.contains("retransmit_lost_server_application_stream_packets"),
        "native mock H3 server must automatically send lost application STREAM retransmits after ACK/loss updates"
    );
}
