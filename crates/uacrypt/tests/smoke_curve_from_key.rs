//! T-257 / D-213: `sign-pubkey`, `sign`, `box-pubkey`, `box-seal` and `box-open` read the curve
//! from the typed key (K3 a); only the keygen commands keep a curve twin. Outputs are compared
//! byte for byte with direct `dstu_core` calls, so a crossed dispatch in the merged commands
//! cannot pass on self-consistency alone. The removed twin names are usage errors (exit 2) that
//! name the replacement.

mod support;
use dstu_core::hazmat::kupyna::Kupyna256;
use support::{assert_key_line, read_bytes, typed_key_line, uacrypt, write_bytes, TempDir};

fn p(path: &std::path::Path) -> &str {
    path.to_str().unwrap()
}

fn ok(r: &support::Run) {
    assert!(r.success(), "code {:?}, stderr: {}", r.code, r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn sign_and_sign_pubkey_follow_the_key_curve_and_match_the_library() {
    let dir = TempDir::new("curve_sign");
    let msg = dir.file("msg");
    let message = b"T-257: one sign command, two curves";
    write_bytes(&msg, message);
    let digest = Kupyna256::digest(message);

    // m=163
    let sk = dir.file("s163.key");
    let vk = dir.file("s163.pub");
    let sig = dir.file("s163.sig");
    ok(&uacrypt(["sign-keygen", "--out", p(&sk)]));
    let d = assert_key_line(&sk, "UACRYPT-SECRET-SIGN163", 21);
    let lib_sk = dstu_core::crypto_sign::SigningKey::from_bytes(&d.try_into().unwrap()).unwrap();
    ok(&uacrypt(["sign-pubkey", "--key", p(&sk), "--out", p(&vk)]));
    assert_eq!(
        String::from_utf8(read_bytes(&vk)).unwrap(),
        typed_key_line(
            "uacrypt-sign163-public",
            &lib_sk.verifying_key().to_uncompressed_bytes()
        )
    );
    ok(&uacrypt([
        "sign",
        "--key",
        p(&sk),
        "--in",
        p(&msg),
        "--out",
        p(&sig),
    ]));
    assert_eq!(
        read_bytes(&sig),
        lib_sk.sign_digest(&digest).to_bytes().to_vec()
    );
    ok(&uacrypt([
        "verify",
        "--key",
        p(&vk),
        "--in",
        p(&msg),
        "--sig",
        p(&sig),
    ]));

    // m=257, same commands
    let sk = dir.file("s257.key");
    let vk = dir.file("s257.pub");
    let sig = dir.file("s257.sig");
    ok(&uacrypt(["sign-keygen257", "--out", p(&sk)]));
    let d = assert_key_line(&sk, "UACRYPT-SECRET-SIGN257", 33);
    let lib_sk = dstu_core::crypto_sign257::SigningKey::from_bytes(&d.try_into().unwrap()).unwrap();
    ok(&uacrypt(["sign-pubkey", "--key", p(&sk), "--out", p(&vk)]));
    assert_eq!(
        String::from_utf8(read_bytes(&vk)).unwrap(),
        typed_key_line(
            "uacrypt-sign257-public",
            &lib_sk.verifying_key().to_uncompressed_bytes()
        )
    );
    ok(&uacrypt([
        "sign",
        "--key",
        p(&sk),
        "--in",
        p(&msg),
        "--out",
        p(&sig),
    ]));
    assert_eq!(
        read_bytes(&sig),
        lib_sk.sign_digest(&digest).to_bytes().to_vec()
    );
    let r = uacrypt(["verify", "--key", p(&vk), "--in", p(&msg), "--sig", p(&sig)]);
    ok(&r);
    assert!(r.stderr.contains("m=257"), "{}", r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn box_commands_follow_the_key_curve_and_match_the_library() {
    let dir = TempDir::new("curve_box");
    let msg = dir.file("msg");
    let message = b"T-257: one box-seal command, two curves";
    write_bytes(&msg, message);

    for (keygen, secret_prefix, public_prefix, key_len, overhead) in [
        (
            "box-keygen",
            "UACRYPT-SECRET-BOX256",
            "uacrypt-box256-public",
            32,
            177,
        ),
        (
            "box-keygen512",
            "UACRYPT-SECRET-BOX512",
            "uacrypt-box512-public",
            64,
            305,
        ),
    ] {
        let sk = dir.file(&format!("{keygen}.key"));
        let pk = dir.file(&format!("{keygen}.pub"));
        let sealed = dir.file(&format!("{keygen}.box"));
        let opened = dir.file(&format!("{keygen}.out"));
        ok(&uacrypt([keygen, "--out", p(&sk)]));
        let raw = assert_key_line(&sk, secret_prefix, key_len);
        let lib_pk = if key_len == 32 {
            dstu_core::crypto_box::SecretKey::from_bytes(&raw.clone().try_into().unwrap())
                .unwrap()
                .public_key()
                .to_bytes()
                .to_vec()
        } else {
            dstu_core::crypto_box512::SecretKey::from_bytes(&raw.clone().try_into().unwrap())
                .unwrap()
                .public_key()
                .to_bytes()
                .to_vec()
        };
        ok(&uacrypt(["box-pubkey", "--key", p(&sk), "--out", p(&pk)]));
        assert_eq!(
            String::from_utf8(read_bytes(&pk)).unwrap(),
            typed_key_line(public_prefix, &lib_pk),
            "{keygen}"
        );
        ok(&uacrypt([
            "box-seal",
            "--key",
            p(&pk),
            "--in",
            p(&msg),
            "--out",
            p(&sealed),
        ]));
        let sealed_bytes = read_bytes(&sealed);
        assert_eq!(sealed_bytes.len(), message.len() + overhead, "{keygen}");
        // The library opens what the CLI sealed, with the curve the key names.
        let lib_opened = if key_len == 32 {
            dstu_core::crypto_box::open(
                &sealed_bytes,
                &dstu_core::crypto_box::SecretKey::from_bytes(&raw.try_into().unwrap()).unwrap(),
            )
            .unwrap()
        } else {
            dstu_core::crypto_box512::open(
                &sealed_bytes,
                &dstu_core::crypto_box512::SecretKey::from_bytes(&raw.try_into().unwrap()).unwrap(),
            )
            .unwrap()
        };
        assert_eq!(lib_opened, message);
        ok(&uacrypt([
            "box-open",
            "--key",
            p(&sk),
            "--in",
            p(&sealed),
            "--out",
            p(&opened),
        ]));
        assert_eq!(read_bytes(&opened), message);
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn a_file_sealed_to_one_curve_is_rejected_by_the_other_curves_key() {
    let dir = TempDir::new("curve_cross_open");
    let msg = dir.file("msg");
    write_bytes(&msg, b"sealed to one curve, opened with the other");
    let k256 = dir.file("k256.key");
    let p256 = dir.file("k256.pub");
    let k512 = dir.file("k512.key");
    let p512 = dir.file("k512.pub");
    ok(&uacrypt(["box-keygen", "--out", p(&k256)]));
    ok(&uacrypt([
        "box-pubkey",
        "--key",
        p(&k256),
        "--out",
        p(&p256),
    ]));
    ok(&uacrypt(["box-keygen512", "--out", p(&k512)]));
    ok(&uacrypt([
        "box-pubkey",
        "--key",
        p(&k512),
        "--out",
        p(&p512),
    ]));

    for (public, wrong_secret, curve) in [(&p256, &k512, "l(p)=512"), (&p512, &k256, "l(p)=256")] {
        let sealed = dir.file("sealed");
        let out = dir.file("out");
        ok(&uacrypt([
            "box-seal",
            "--key",
            p(public),
            "--in",
            p(&msg),
            "--out",
            p(&sealed),
            "--force",
        ]));
        let r = uacrypt([
            "box-open",
            "--key",
            p(wrong_secret),
            "--in",
            p(&sealed),
            "--out",
            p(&out),
        ]);
        assert_eq!(r.code, Some(1), "{}", r.stderr);
        assert!(
            r.stderr.contains(curve),
            "names the key's curve: {}",
            r.stderr
        );
        assert!(!out.exists(), "no output on a rejected open");
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn an_m163_signature_does_not_verify_under_an_m257_key() {
    let dir = TempDir::new("curve_cross_verify");
    let msg = dir.file("msg");
    write_bytes(&msg, b"signed on m=163");
    let s163 = dir.file("s163.key");
    let s257 = dir.file("s257.key");
    let v257 = dir.file("s257.pub");
    let sig = dir.file("sig");
    ok(&uacrypt(["sign-keygen", "--out", p(&s163)]));
    ok(&uacrypt(["sign-keygen257", "--out", p(&s257)]));
    ok(&uacrypt([
        "sign-pubkey",
        "--key",
        p(&s257),
        "--out",
        p(&v257),
    ]));
    ok(&uacrypt([
        "sign",
        "--key",
        p(&s163),
        "--in",
        p(&msg),
        "--out",
        p(&sig),
    ]));
    let r = uacrypt([
        "verify",
        "--key",
        p(&v257),
        "--in",
        p(&msg),
        "--sig",
        p(&sig),
    ]);
    assert!(r.failure(), "{}", r.stderr);
    assert!(!r.stderr.contains("Signature OK"));
}

const REMOVED: [(&str, &str); 5] = [
    ("sign-pubkey257", "sign-pubkey"),
    ("sign257", "sign"),
    ("box-pubkey512", "box-pubkey"),
    ("box-seal512", "box-seal"),
    ("box-open512", "box-open"),
];

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn removed_twin_commands_are_usage_errors_naming_the_replacement() {
    let dir = TempDir::new("curve_removed");
    let key = dir.file("any.key");
    let out = dir.file("out");
    ok(&uacrypt(["box-keygen512", "--out", p(&key)]));
    for (old, new) in REMOVED {
        for args in [
            vec![old, "--key", p(&key), "--in", p(&key), "--out", p(&out)],
            vec![old, "--help"],
            vec!["help", old],
        ] {
            let r = uacrypt(&args);
            assert_eq!(r.code, Some(2), "{args:?}: {}", r.stderr);
            assert!(
                r.stderr.contains(&format!("`uacrypt {new}`")),
                "{args:?}: {}",
                r.stderr
            );
            assert!(r.stdout.is_empty(), "{args:?}: {}", r.stdout);
            assert!(!out.exists(), "{args:?} wrote output");
        }
    }
    let r = uacrypt(["help"]);
    ok(&r);
    for (old, _) in REMOVED {
        assert!(
            !r.stdout.contains(&format!("    {old} ")),
            "top-level help still lists {old}"
        );
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn wrong_kind_keys_point_to_the_one_right_command() {
    let dir = TempDir::new("curve_wrong_kind");
    let msg = dir.file("msg");
    let out = dir.file("out");
    write_bytes(&msg, b"x");
    let box512 = dir.file("box512.key");
    let box256 = dir.file("box256.key");
    ok(&uacrypt(["box-keygen512", "--out", p(&box512)]));
    ok(&uacrypt(["box-keygen", "--out", p(&box256)]));

    let r = uacrypt([
        "box-seal",
        "--key",
        p(&box512),
        "--in",
        p(&msg),
        "--out",
        p(&out),
    ]);
    assert_eq!(r.code, Some(3), "{}", r.stderr);
    assert_eq!(
        r.stderr.matches("`uacrypt box-pubkey`").count(),
        1,
        "{}",
        r.stderr
    );
    assert!(!r.stderr.contains("512`"), "no twin hint: {}", r.stderr);
    assert!(!out.exists());

    let r = uacrypt([
        "sign",
        "--key",
        p(&box256),
        "--in",
        p(&msg),
        "--out",
        p(&out),
    ]);
    assert_eq!(r.code, Some(3), "{}", r.stderr);
    assert!(r.stderr.contains("`uacrypt sign-keygen`"), "{}", r.stderr);
    assert!(
        r.stderr.contains("`uacrypt sign-keygen257`"),
        "{}",
        r.stderr
    );
    assert!(!out.exists());
}
