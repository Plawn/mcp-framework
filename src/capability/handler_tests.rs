use super::*;

#[test]
fn summarize_content_empty() {
    assert_eq!(summarize_content(&[]), None);
}

#[test]
fn summarize_content_text_truncation() {
    let long_text = "x".repeat(300);
    let content = vec![ContentBlock::text(long_text)];
    let summary = summarize_content(&content).unwrap();
    assert!(summary.len() < 270);
    assert!(summary.ends_with("..."));
}

#[test]
fn summarize_content_short_text() {
    let content = vec![ContentBlock::text("hello")];
    let summary = summarize_content(&content).unwrap();
    assert_eq!(summary, "hello");
}

#[test]
fn summarize_content_mixed() {
    let content = vec![
        ContentBlock::text("hello"),
        ContentBlock::image("base64data", "image/png"),
    ];
    let summary = summarize_content(&content).unwrap();
    assert_eq!(summary, "hello; <image>");
}
