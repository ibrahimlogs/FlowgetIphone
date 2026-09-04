use flowget_flowshare_core::{
    candidates::{candidate_payload_digest, NativeCandidate},
    protocol::{resume_state_digest, RangeHeader, NATIVE_QUIC_PROTOCOL_VERSION},
    secure_protocol::{
        capability_digest, checkpoint_mac, secure_resume_state_digest, session_lineage_digest,
        transfer_commitment,
    },
};
use serde_json::Value;

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect()
}

#[test]
fn flowshare_v3_matches_language_neutral_golden_vectors() {
    let value: Value =
        serde_json::from_str(include_str!("../golden-vectors/flowshare-v3.json")).unwrap();
    assert_eq!(value["wireProtocolVersion"], NATIVE_QUIC_PROTOCOL_VERSION);

    let range = RangeHeader {
        transfer_id: [0x11; 16],
        range_id: 0x0102_0304,
        offset: 0x0102_0304_0506_0708,
        length: 0x1112_1314_1516_1718,
        flags: 0x2122,
    };
    assert_eq!(hex(range.encode()), value["rangeHeader"]["encodedHex"]);
    assert_eq!(RangeHeader::decode(&range.encode()).unwrap(), range);

    let bitmap = [0b1010_0101, 0b0000_0011];
    assert_eq!(
        hex(resume_state_digest(10, &bitmap)),
        value["resumeStateDigest"]["sha256Hex"]
    );
    assert_eq!(
        hex(capability_digest(7)),
        value["capabilityDigest"]["sha256Hex"]
    );
    assert_eq!(
        hex(session_lineage_digest(Some(&[0x22; 16]))),
        value["sessionLineageDigest"]["sha256Hex"]
    );
    assert_eq!(
        hex(transfer_commitment(123456789, &[0x33; 32], 2097152, 59, 7)),
        value["transferCommitment"]["sha256Hex"]
    );
    assert_eq!(
        hex(secure_resume_state_digest(
            &[0x11; 16],
            9,
            123456789,
            2097152,
            59,
            &bitmap,
            6291456,
            &[0x44; 32],
            &[0x33; 32],
            &[0x55; 32]
        )),
        value["secureResumeStateDigest"]["sha256Hex"]
    );
    assert_eq!(
        hex(checkpoint_mac(&[0x66; 32], b"flowget-golden-checkpoint-v3").unwrap()),
        value["checkpointMac"]["tagHex"]
    );

    let candidate: NativeCandidate =
        serde_json::from_value(value["candidate"]["canonicalJson"].clone()).unwrap();
    candidate.validate(false, 4_000_000_000_000).unwrap();
    assert_eq!(
        hex(candidate_payload_digest(&[candidate])),
        value["candidate"]["batchDigestHex"]
    );
}
