use specter::fingerprint::http2::Http2Settings;
use specter::transport::h2::{SettingsFrame, SettingsId};

#[test]
fn rfc8441_settings_id_supports_enable_connect_protocol() {
    assert_eq!(u16::from(SettingsId::EnableConnectProtocol), 0x8);
    assert_eq!(
        SettingsId::try_from(0x8),
        Ok(SettingsId::EnableConnectProtocol)
    );
    assert!(
        SettingsId::try_from(0x4a4a).is_err(),
        "unknown settings must not alias HEADER_TABLE_SIZE"
    );
}

#[test]
fn rfc8441_settings_frame_preserves_raw_enable_connect_protocol_id() {
    let mut frame = SettingsFrame::new();
    frame
        .set(SettingsId::HeaderTableSize, 4096)
        .set(SettingsId::EnableConnectProtocol, 1)
        .set(0xaaaa_u16, 0);

    let bytes = frame.serialize().freeze();
    let parsed = SettingsFrame::parse(0, bytes.slice(9..));

    assert_eq!(
        parsed.settings,
        vec![
            (u16::from(SettingsId::HeaderTableSize), 4096),
            (0x8, 1),
            (0xaaaa, 0),
        ]
    );
}

#[test]
fn rfc8441_client_initial_settings_do_not_advertise_enable_connect_protocol() {
    let settings = Http2Settings::default();
    let mut frame = SettingsFrame::new();

    frame
        .set(SettingsId::HeaderTableSize, settings.header_table_size)
        .set(
            SettingsId::EnablePush,
            if settings.enable_push { 1 } else { 0 },
        )
        .set(
            SettingsId::MaxConcurrentStreams,
            settings.max_concurrent_streams,
        )
        .set(SettingsId::InitialWindowSize, settings.initial_window_size)
        .set(SettingsId::MaxFrameSize, settings.max_frame_size)
        .set(SettingsId::MaxHeaderListSize, settings.max_header_list_size)
        .set(0x0a0a_u16, 0);

    assert!(
        frame.settings.iter().all(|(id, _)| *id != 0x8),
        "client initial HTTP/2 SETTINGS must not advertise RFC 8441 support"
    );
}
