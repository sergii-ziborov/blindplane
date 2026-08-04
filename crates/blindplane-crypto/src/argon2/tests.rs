//! Unit tests for BLAKE2b and Argon2id.

use super::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn blake2b_rfc7693_abc() {
    let digest: [u8; 64] = Blake2b::digest(b"abc");
    assert_eq!(
        hex(&digest),
        concat!(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1",
            "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        )
    );
}

#[test]
fn blake2b_empty_input() {
    let digest: [u8; 64] = Blake2b::digest(b"");
    assert_eq!(
        hex(&digest),
        concat!(
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419",
            "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        )
    );
}

#[test]
fn blake2b_short_output() {
    let digest: [u8; 32] = Blake2b::digest(b"");
    assert_eq!(
        hex(&digest),
        "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
    );
}

#[test]
fn blake2b_streaming_matches_one_shot() {
    let data: Vec<u8> = (0..500_u32).map(|i| (i * 3) as u8).collect();
    let mut hasher = Blake2b::new(64);
    for chunk in data.chunks(17) {
        hasher.update(chunk);
    }
    let mut streamed = [0_u8; 64];
    hasher.finalize_into(&mut streamed);
    let one_shot: [u8; 64] = Blake2b::digest(&data);
    assert_eq!(streamed, one_shot);
}

#[test]
fn argon2id_is_deterministic_and_parameter_bound() {
    let params = Argon2Params {
        memory_kib: 64,
        passes: 2,
        output_len: 32,
    };
    let a = argon2id(b"password", b"saltsaltsaltsalt", params).unwrap();
    let b = argon2id(b"password", b"saltsaltsaltsalt", params).unwrap();
    assert_eq!(a, b);

    let different_salt = argon2id(b"password", b"other-salt-here!", params).unwrap();
    assert_ne!(a, different_salt);

    let different_password = argon2id(b"password2", b"saltsaltsaltsalt", params).unwrap();
    assert_ne!(a, different_password);

    let more_passes = argon2id(
        b"password",
        b"saltsaltsaltsalt",
        Argon2Params {
            passes: 3,
            ..params
        },
    )
    .unwrap();
    assert_ne!(a, more_passes);
}

#[test]
fn argon2id_rejects_weak_parameters() {
    let params = Argon2Params {
        memory_kib: 4,
        passes: 1,
        output_len: 32,
    };
    assert_eq!(argon2id(b"p", b"saltsalt", params), Err(InvalidParams));
    assert_eq!(
        argon2id(
            b"p",
            b"short",
            Argon2Params {
                memory_kib: 64,
                ..params
            }
        ),
        Err(InvalidParams)
    );
}
