//! Known-answer suite for v1 Gate 2.
//!
//! `cargo test kat` runs this binary. Vectors are external:
//! RFC 7748 X25519 (section 5.2, the iteration test, section 6.1),
//! RFC 5869 HKDF-SHA256 (appendix A.1–A.3), and the vendored Wycheproof
//! files in `testdata/kat/`. X448 and HKDF-SHA1 are not implemented.

use std::path::PathBuf;

use serde::Deserialize;
use voicechat_crypto::primitives::kdf::{hkdf_extract_expand, hmac_sha256, hmac_sha512};
use voicechat_crypto::primitives::x25519::{X25519Public, X25519Secret};

fn hex_bytes(label: &str, id: u32, hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).unwrap_or_else(|e| panic!("{label} tc {id}: bad hex: {e}"))
}

fn arr32(label: &str, id: u32, hex_str: &str) -> [u8; 32] {
    let bytes = hex_bytes(label, id, hex_str);
    bytes
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("{label} tc {id}: expected 32 bytes, got {}", v.len()))
}

/// Raw X25519(k, u). Rejects only the all-zero public encoding, which
/// `X25519Public::from_bytes` refuses. RFC 7748 allows that refusal.
fn x25519(k: [u8; 32], u: [u8; 32]) -> Result<[u8; 32], ()> {
    let public = X25519Public::from_bytes(u).map_err(|_| ())?;
    Ok(X25519Secret::from_bytes(k).diffie_hellman(&public))
}

/// RFC 7748 §5.2: each iteration sets k to X25519(k, u) and u to the old k.
fn x25519_iterate(iterations: u32) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = 9;
    let mut u = k;
    for _ in 0..iterations {
        let out = x25519(k, u).expect("iteration u-coordinate");
        u = k;
        k = out;
    }
    k
}

#[test]
fn kat_rfc7748_x25519_direct_and_dh() {
    // §5.2, two direct calls.
    let cases = [
        (
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        ),
        (
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        ),
    ];
    for (i, (k, u, out)) in cases.iter().enumerate() {
        let id = i as u32 + 1;
        assert_eq!(
            x25519(arr32("rfc7748-5.2", id, k), arr32("rfc7748-5.2", id, u)).unwrap(),
            arr32("rfc7748-5.2", id, out)
        );
    }

    // §6.1 Diffie-Hellman. Public keys are X25519(scalar, 9).
    let alice = arr32(
        "rfc7748-6.1",
        1,
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    );
    let bob = arr32(
        "rfc7748-6.1",
        2,
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    );
    let mut base = [0u8; 32];
    base[0] = 9;
    let alice_public = x25519(alice, base).unwrap();
    let bob_public = x25519(bob, base).unwrap();
    assert_eq!(
        alice_public,
        arr32(
            "rfc7748-6.1",
            3,
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        )
    );
    assert_eq!(
        bob_public,
        arr32(
            "rfc7748-6.1",
            4,
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        )
    );
    let shared = arr32(
        "rfc7748-6.1",
        5,
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    );
    assert_eq!(x25519(alice, bob_public).unwrap(), shared);
    assert_eq!(x25519(bob, alice_public).unwrap(), shared);
}

#[test]
fn kat_rfc7748_x25519_iterations() {
    assert_eq!(
        x25519_iterate(1),
        arr32(
            "rfc7748-iter",
            1,
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
        )
    );
    assert_eq!(
        x25519_iterate(1_000),
        arr32(
            "rfc7748-iter",
            1000,
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
        )
    );
    assert_eq!(
        x25519_iterate(1_000_000),
        arr32(
            "rfc7748-iter",
            1_000_000,
            "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"
        )
    );
}

fn hkdf_okm(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut okm = vec![0u8; len];
    hkdf_extract_expand(salt, ikm, info, &mut okm).unwrap();
    okm
}

#[test]
fn kat_rfc5869_hkdf_sha256() {
    // A.1. IKM is 22 bytes of 0x0b. Salt is present.
    let ikm1 = [0x0bu8; 22];
    let salt1 = hex::decode("000102030405060708090a0b0c").unwrap();
    let info1 = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let prk1 = hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").unwrap();
    let okm1 = hex::decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865").unwrap();
    assert_eq!(hmac_sha256(&salt1, &ikm1).to_vec(), prk1);
    assert_eq!(hkdf_okm(Some(&salt1), &ikm1, &info1, 42), okm1);

    // A.2. Longer inputs.
    let ikm2 = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f").unwrap();
    let salt2 = hex::decode("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf").unwrap();
    let info2 = hex::decode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
    let prk2 = hex::decode("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244").unwrap();
    let okm2 = hex::decode("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87").unwrap();
    assert_eq!(hmac_sha256(&salt2, &ikm2).to_vec(), prk2);
    assert_eq!(hkdf_okm(Some(&salt2), &ikm2, &info2, 82), okm2);

    // A.3. Zero-length salt and info. This is not "salt omitted" (that would
    // be HashLen zero bytes). Pass Some(empty).
    let prk3 = hex::decode("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04").unwrap();
    let okm3 = hex::decode("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8").unwrap();
    assert_eq!(hmac_sha256(&[], &ikm1).to_vec(), prk3);
    assert_eq!(hkdf_okm(Some(&[]), &ikm1, &[], 42), okm3);
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct XdhSuite {
    number_of_tests: usize,
    test_groups: Vec<XdhGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct XdhGroup {
    curve: String,
    tests: Vec<XdhCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct XdhCase {
    tc_id: u32,
    public: String,
    private: String,
    shared: String,
    result: String,
}

#[test]
fn kat_wycheproof_x25519() {
    let raw = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/kat/x25519_test.json"
    ));
    let suite: XdhSuite = serde_json::from_str(raw).expect("x25519 wycheproof json");
    let mut seen = 0usize;
    for group in &suite.test_groups {
        assert_eq!(group.curve, "curve25519");
        for case in &group.tests {
            seen += 1;
            let k = arr32("wycheproof-x25519", case.tc_id, &case.private);
            let u = arr32("wycheproof-x25519", case.tc_id, &case.public);
            let shared = arr32("wycheproof-x25519", case.tc_id, &case.shared);
            match case.result.as_str() {
                "valid" => {
                    let got = x25519(k, u).unwrap_or_else(|_| {
                        panic!("wycheproof x25519 tc {} marked valid but public was rejected", case.tc_id)
                    });
                    assert_eq!(got, shared, "wycheproof x25519 tc {}", case.tc_id);
                }
                "acceptable" => {
                    // RFC 7748 allows rejecting a low-order / all-zero output
                    // or an all-zero public. If we compute, the bytes must match.
                    if let Ok(got) = x25519(k, u) {
                        assert_eq!(got, shared, "wycheproof x25519 tc {}", case.tc_id);
                    }
                }
                other => panic!("wycheproof x25519 tc {}: unexpected result {other}", case.tc_id),
            }
        }
    }
    assert_eq!(seen, suite.number_of_tests);
    assert!(seen >= 100, "x25519 file should itself clear the 100-vector bar");
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MacSuite {
    number_of_tests: usize,
    test_groups: Vec<MacGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MacGroup {
    tag_size: usize,
    tests: Vec<MacCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MacCase {
    tc_id: u32,
    key: String,
    msg: String,
    tag: String,
    result: String,
}

fn kat_wycheproof_hmac(path: &str, which: &str, mac: fn(&[u8], &[u8]) -> Vec<u8>) {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let suite: MacSuite = serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{which} json: {e}"));
    let mut seen = 0usize;
    for group in &suite.test_groups {
        assert!(group.tag_size % 8 == 0, "{which} tagSize {}", group.tag_size);
        let tag_len = group.tag_size / 8;
        for case in &group.tests {
            seen += 1;
            let key = hex_bytes(which, case.tc_id, &case.key);
            let msg = hex_bytes(which, case.tc_id, &case.msg);
            let expected = hex_bytes(which, case.tc_id, &case.tag);
            assert_eq!(
                expected.len(),
                tag_len,
                "{which} tc {} tag length",
                case.tc_id
            );
            let full = mac(&key, &msg);
            assert!(
                full.len() >= tag_len,
                "{which} tc {} mac shorter than tag",
                case.tc_id
            );
            let got = &full[..tag_len];
            match case.result.as_str() {
                "valid" => assert_eq!(got, expected.as_slice(), "{which} tc {}", case.tc_id),
                "invalid" => assert_ne!(got, expected.as_slice(), "{which} tc {}", case.tc_id),
                other => panic!("{which} tc {}: unexpected result {other}", case.tc_id),
            }
        }
    }
    assert_eq!(seen, suite.number_of_tests);
}

#[test]
fn kat_wycheproof_hmac_sha256() {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("testdata/kat/hmac_sha256_test.json");
    kat_wycheproof_hmac(
        path.to_str().unwrap(),
        "wycheproof-hmac-sha256",
        |key, msg| hmac_sha256(key, msg).to_vec(),
    );
}

#[test]
fn kat_wycheproof_hmac_sha512() {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("testdata/kat/hmac_sha512_test.json");
    kat_wycheproof_hmac(
        path.to_str().unwrap(),
        "wycheproof-hmac-sha512",
        |key, msg| hmac_sha512(key, msg).to_vec(),
    );
}
