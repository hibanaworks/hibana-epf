#![cfg(feature = "std")]

use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[test]
fn recorded_frame_reaches_the_vm_with_its_ordinal_lane_and_full_wire_label() {
    let path = std::env::temp_dir().join(format!(
        "epf-frame-{}-{}.hbt",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let record = [0, 0, 0, 7, 0x02, 0x06, 0xa5, 0, 0, 0, 0, 42, 1, 2, 1, 0];
    File::create_new(&path).unwrap().write_all(&record).unwrap();
    let executable = env!("CARGO_BIN_EXE_hibana-epf");
    let explanation = Command::new(executable)
        .arg("explain-tap")
        .arg(&path)
        .output()
        .unwrap();
    let diagnosis = Command::new(executable)
        .args(["diagnose", "match", "3", "0x0206a500", "73", "9"])
        .arg(&path)
        .output()
        .unwrap();
    fs::write(&path, &record[..15]).unwrap();
    let truncated = Command::new(executable)
        .arg("explain-tap")
        .arg(&path)
        .output()
        .unwrap();
    fs::remove_file(path).unwrap();

    assert!(!truncated.status.success());
    assert!(truncated.stdout.is_empty());
    assert!(explanation.status.success(), "{explanation:?}");
    let text = String::from_utf8(explanation.stdout).unwrap();
    assert!(text.contains("ts=7 id=0x0206 causal=0xa500"), "{text}");
    assert!(
        text.contains("input=[0x0000002a,0x01020100,0x00000000,0x0206a500]"),
        "{text}"
    );
    assert!(diagnosis.status.success(), "{diagnosis:?}");
    let text = String::from_utf8(diagnosis.stdout).unwrap();
    assert!(text.contains("kind=73 reason=9"), "{text}");
    assert!(text.contains("arg1=0x01020100 arg2=0x0206a500"), "{text}");
}

#[test]
fn stream_emits_each_record_before_eof_and_rejects_a_partial_final_record() {
    let output_path = std::env::temp_dir().join(format!(
        "epf-live-{}-{}.hepo",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut child = Command::new(env!("CARGO_BIN_EXE_hibana-epf"))
        .args(["stream", "--recipe", "echo", "--out"])
        .arg(&output_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let mut input = child.stdin.take().unwrap();
    let first = [0, 0, 0, 7, 0x02, 0x06, 0xa5, 0, 0, 0, 0, 42, 1, 2, 1, 0];
    let mut second = first;
    second[3] = 8;
    second[6] = 0x11;
    let result = (|| -> Result<(), String> {
        // Each partial write must be combined into one canonical observation.
        for record in [first, second] {
            input.write_all(&record[..5]).map_err(|e| e.to_string())?;
            input.flush().map_err(|e| e.to_string())?;
            if receiver.try_recv().is_ok() {
                return Err("a partial record produced output".into());
            }
            input.write_all(&record[5..]).map_err(|e| e.to_string())?;
            input.flush().map_err(|e| e.to_string())?;
            let line = receiver
                .recv_timeout(Duration::from_secs(10))
                .map_err(|e| format!("no observation before EOF: {e}"))?
                .map_err(|e| e.to_string())?;
            if !line.contains(&format!("tap_ts={}", record[3])) {
                return Err(format!("observation ordinal lost: {line}"));
            }
            if child.try_wait().map_err(|e| e.to_string())?.is_some() {
                return Err("stream exited before its input closed".into());
            }
        }
        let bytes = fs::read(&output_path).map_err(|e| e.to_string())?;
        if bytes.len() != 2 * hibana_epf::CompactOutRecord::SIZE {
            return Err("binary observations were buffered until EOF".into());
        }
        let (records, _) = bytes.as_chunks::<{ hibana_epf::CompactOutRecord::SIZE }>();
        let a = hibana_epf::CompactOutRecord::decode(&records[0]).unwrap();
        let b = hibana_epf::CompactOutRecord::decode(&records[1]).unwrap();
        if (a.arg1, a.arg2, b.arg1, b.arg2) != (0x01020100, 0x0206a500, 0x01020100, 0x02061100) {
            return Err("binary observations lost their wire metadata".into());
        }
        input.write_all(&first[..15]).map_err(|e| e.to_string())?;
        Ok(())
    })();
    drop(input);
    if result.is_err() {
        let _ = child.kill();
    }
    let output = child.wait_with_output().unwrap();
    reader.join().unwrap();
    let cleanup = fs::remove_file(&output_path);
    result.unwrap();
    cleanup.unwrap();
    assert!(!output.status.success(), "partial final record accepted");
    assert!(String::from_utf8_lossy(&output.stderr).contains("tap record #2 (expected 16 bytes)"));
}

#[test]
fn streaming_output_cannot_overwrite_its_input_capture() {
    let path = std::env::temp_dir().join(format!(
        "epf-existing-{}-{}.hbt",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let record = [0, 0, 0, 7, 0x02, 0x06, 0xa5, 0, 0, 0, 0, 42, 1, 2, 1, 0];
    File::create_new(&path).unwrap().write_all(&record).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_hibana-epf"))
        .args(["replay", "--out"])
        .arg(&path)
        .arg(&path)
        .output()
        .unwrap();
    let retained = fs::read(&path).unwrap();
    fs::remove_file(path).unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(retained, record);
}

#[test]
fn stream_finishes_successfully_at_a_record_boundary() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hibana-epf"))
        .args(["stream", "--recipe", "echo"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let record = [0, 0, 0, 7, 0x02, 0x06, 0xa5, 0, 0, 0, 0, 42, 1, 2, 1, 0];
    child.stdin.take().unwrap().write_all(&record).unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success(), "{result:?}");
    assert_eq!(String::from_utf8_lossy(&result.stdout).lines().count(), 1);
    assert!(result.stderr.is_empty());
}
