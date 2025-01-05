use assert_cmd::Command;
use std::{
    env::set_current_dir,
    fs::{remove_file, write},
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
