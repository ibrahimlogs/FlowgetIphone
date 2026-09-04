use flowget_flowshare_core::{
    candidates::{candidate_payload_digest, NativeCandidate, NativeCandidateType},
    protocol::{resume_state_digest, RangeHeader},
    secure_protocol::{
        capability_digest, checkpoint_mac, secure_resume_state_digest, session_lineage_digest,
        transfer_commitment,
    },
};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr};

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect()
}

fn main() {
    let transfer_id = [0x11; 16];
    let range = RangeHeader {
        transfer_id,
        range_id: 0x0102_0304,
        offset: 0x0102_0304_0506_0708,
        length: 0x1112_1314_1516_1718,
        flags: 0x2122,
    };
    let candidate = NativeCandidate::new(
        NativeCandidateType::Host,
        IpAddr::V4(Ipv4Addr::new(192, 168, 50, 7)),
        44321,
        "golden-lan".into(),
        2_130_706_431,
        "host-v4-golden".into(),
        None,
        3,
        4_102_444_800_000,
    )
    .unwrap();
    let bitmap = [0b1010_0101, 0b0000_0011];
    let output = json!({
        "schemaVersion": 1,
        "wireProtocolVersion": 3,
        "rangeHeader": {
            "input": {"transferIdHex": hex(transfer_id), "rangeId": range.range_id, "offset": range.offset, "length": range.length, "flags": range.flags},
            "encodedHex": hex(range.encode())
        },
        "resumeStateDigest": {"totalBlocks": 10, "bitmapHex": hex(bitmap), "sha256Hex": hex(resume_state_digest(10, &bitmap))},
        "capabilityDigest": {"capabilities": 7, "sha256Hex": hex(capability_digest(7))},
        "sessionLineageDigest": {"sessionIdHex": hex([0x22; 16]), "sha256Hex": hex(session_lineage_digest(Some(&[0x22; 16])))},
        "transferCommitment": {"fileSize": 123456789u64, "expectedSha256Hex": hex([0x33; 32]), "blockSize": 2097152u64, "totalBlocks": 59u64, "capabilities": 7u64, "sha256Hex": hex(transfer_commitment(123456789, &[0x33; 32], 2097152, 59, 7))},
        "secureResumeStateDigest": {"sha256Hex": hex(secure_resume_state_digest(&transfer_id, 9, 123456789, 2097152, 59, &bitmap, 6291456, &[0x44; 32], &[0x33; 32], &[0x55; 32]))},
        "checkpointMac": {"keyHex": hex([0x66; 32]), "payloadHex": hex(b"flowget-golden-checkpoint-v3"), "tagHex": hex(checkpoint_mac(&[0x66; 32], b"flowget-golden-checkpoint-v3").unwrap())},
        "candidate": {"canonicalJson": candidate, "batchDigestHex": hex(candidate_payload_digest(&[candidate.clone()]))}
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
