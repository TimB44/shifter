use assert_cmd::Command;
use std::{
    env::set_current_dir,
    fs::{exists, remove_file, write},
};

const TMPDIR: &str = env!("CARGO_TARGET_TMPDIR");
#[test]
fn basic() {
    set_current_dir(TMPDIR).unwrap();

    let file_contents = b"this is the content, 123";
    write("basic.txt", file_contents).unwrap();
    let mut encrypt_command = Command::cargo_bin("shifter").unwrap();
    encrypt_command.args([
        "encrypt",
        "basic.txt",
        "--password",
        "TESTPW",
        "--outfile",
        "secret.shifted",
    ]);

    encrypt_command.assert().success();

    remove_file("basic.txt").unwrap();
    let mut decrypt_command = Command::cargo_bin("shifter").unwrap();
    decrypt_command.args(["decrypt", "secret.shifted", "--password", "TESTPW"]);
    decrypt_command.assert().success();

    assert_eq!(
        &file_contents,
        &std::fs::read("basic.txt").unwrap().as_slice()
    );

    remove_file("secret.shifted").unwrap();
    remove_file("basic.txt").unwrap();
}

#[test]
fn shortnames() {
    set_current_dir(TMPDIR).unwrap();

    let file_contents = b"this is the content, 12345678";
    write("short.txt", file_contents).unwrap();
    let mut encrypt_command = Command::cargo_bin("shifter").unwrap();
    encrypt_command.args([
        "e",
        "short.txt",
        "-p",
        "THISISAPASSWORD",
        "-o",
        "shortsecret.shifted",
    ]);

    encrypt_command.assert().success();

    remove_file("short.txt").unwrap();
    let mut decrypt_command = Command::cargo_bin("shifter").unwrap();
    decrypt_command.args(["d", "shortsecret.shifted", "-p", "THISISAPASSWORD"]);
    decrypt_command.assert().success();

    assert_eq!(
        &file_contents,
        &std::fs::read("short.txt").unwrap().as_slice()
    );

    remove_file("shortsecret.shifted").unwrap();
    remove_file("short.txt").unwrap();
}

#[test]
fn password_from_file() {
    set_current_dir(TMPDIR).unwrap();

    let file_contents = b"super secret data";
    let password = b"this password is coming from a file";
    write("password.txt", password).unwrap();
    write("data.txt", file_contents).unwrap();
    let mut encrypt_command = Command::cargo_bin("shifter").unwrap();
    encrypt_command.args([
        "e",
        "data.txt",
        "--password-file",
        "password.txt",
        "-o",
        "output.shifted",
    ]);

    encrypt_command.assert().success();

    remove_file("data.txt").unwrap();
    let mut decrypt_command = Command::cargo_bin("shifter").unwrap();
    decrypt_command.args(["d", "output.shifted", "--password-file", "password.txt"]);
    decrypt_command.assert().success();

    assert_eq!(
        &file_contents,
        &std::fs::read("data.txt").unwrap().as_slice()
    );

    remove_file("output.shifted").unwrap();
    remove_file("data.txt").unwrap();
    remove_file("password.txt").unwrap();
}

#[test]
fn differnt_passwords_fail() {
    set_current_dir(TMPDIR).unwrap();
    let file_contents = b"BIG SECRET";
    write("abc.c", file_contents).unwrap();
    let mut encrypt_command = Command::cargo_bin("shifter").unwrap();
    encrypt_command.args(["e", "abc.c", "-p", "1", "-o", "ops.shifted"]);

    encrypt_command.assert().success();

    remove_file("abc.c").unwrap();
    Command::cargo_bin("shifter")
        .unwrap()
        .args(["d", "ops.shifted", "-p", "2"])
        .assert()
        .failure();

    remove_file("ops.shifted").unwrap();
}

#[test]
fn generated_passphrase() {
    set_current_dir(TMPDIR).unwrap();
    for _ in 0..100 {
        let data = b"FILE CONTENTS";
        write("secret.png", data).unwrap();
        let assert = Command::cargo_bin("shifter")
            .unwrap()
            .args(["e", "secret.png", "-o", "img.shifted"])
            .assert()
            .success();

        let output = assert.get_output();

        let output_string = &String::from_utf8_lossy(&output.stdout);
        let pw = &output_string
            .lines()
            .find(|l| l.contains("Generated passphrase:"))
            .unwrap()[22..];

        remove_file("secret.png").unwrap();

        Command::cargo_bin("shifter")
            .unwrap()
            .args(["d", "img.shifted", "-p", pw])
            .assert()
            .success();

        assert_eq!(&data, &std::fs::read("secret.png").unwrap().as_slice());
        remove_file("img.shifted").unwrap();
        remove_file("secret.png").unwrap();
    }
}

#[test]
fn generated_passphrase_length() {
    set_current_dir(TMPDIR).unwrap();
    for length in 1..50 {
        let data = b"hello world!";
        write("info.md", data).unwrap();
        let assert = Command::cargo_bin("shifter")
            .unwrap()
            .args([
                "e",
                "info.md",
                "-o",
                "out.shifted",
                "-l",
                &length.to_string(),
            ])
            .assert()
            .success();

        let output = assert.get_output();

        let output_string = &String::from_utf8_lossy(&output.stdout);
        let pf = &output_string
            .lines()
            .find(|l| l.contains("Generated passphrase:"))
            .unwrap()[22..];

        assert_eq!(pf.chars().filter(|&x| x == '-').count(), length - 1);
        remove_file("info.md").unwrap();

        Command::cargo_bin("shifter")
            .unwrap()
            .args(["d", "out.shifted", "-p", pf])
            .assert()
            .success();

        assert_eq!(&data, &std::fs::read("info.md").unwrap().as_slice());
        remove_file("out.shifted").unwrap();
        remove_file("info.md").unwrap();
    }
}

#[test]
fn delete_flag() {
    set_current_dir(TMPDIR).unwrap();

    let file_contents = b"this is the content, 123";
    write("del.txt", file_contents).unwrap();
    let mut encrypt_command = Command::cargo_bin("shifter").unwrap();
    encrypt_command.args([
        "encrypt",
        "del.txt",
        "--password",
        "TESTPW",
        "--outfile",
        "del.shifted",
        "--delete",
    ]);

    encrypt_command.assert().success();

    assert!(!exists("del.txt").unwrap());
    let mut decrypt_command = Command::cargo_bin("shifter").unwrap();
    decrypt_command.args(["decrypt", "del.shifted", "--password", "TESTPW", "-d"]);
    decrypt_command.assert().success();

    assert_eq!(
        &file_contents,
        &std::fs::read("del.txt").unwrap().as_slice()
    );

    assert!(!exists("del.shifted").unwrap());
    remove_file("del.txt").unwrap();
}
