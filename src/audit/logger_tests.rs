use super::*;
use crate::audit::record::{ToolCallOutcome, ToolCallRecord, ToolCallSource};
use crate::newtypes::{SessionId, ToolName};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

fn sample_record() -> ToolCallRecord {
    ToolCallRecord {
        tool_name: ToolName::new("test_tool"),
        arguments: None,
        session_id: SessionId::new("sess-1"),
        timestamp: SystemTime::now(),
        duration: Duration::from_millis(42),
        source: ToolCallSource::Inner,
        outcome: ToolCallOutcome::Success {
            is_error: false,
            content_summary: Some("hello".to_string()),
        },
    }
}

#[tokio::test]
async fn noop_logger_completes() {
    let logger = NoopLogger;
    logger.log(sample_record()).await;
}

#[tokio::test]
async fn tracing_logger_does_not_panic() {
    let logger = TracingLogger;
    logger.log(sample_record()).await;
}

#[tokio::test]
async fn custom_logger_receives_record() {
    static COUNT: AtomicU32 = AtomicU32::new(0);

    struct CountingLogger;
    impl ToolCallLogger for CountingLogger {
        fn log(
            &self,
            _record: ToolCallRecord,
        ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            COUNT.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::ready(()))
        }
    }

    let logger = CountingLogger;
    logger.log(sample_record()).await;
    assert_eq!(COUNT.load(Ordering::SeqCst), 1);
}
