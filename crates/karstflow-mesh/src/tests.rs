use crate::{bounded_link, SendError};

#[test]
fn bounded_link_counts_blocked_send_when_queue_is_full() {
    let (outbound, _inbound) = bounded_link::<u64>(1);

    assert!(outbound.try_send(7).is_ok());
    assert!(matches!(outbound.try_send(9), Err(SendError::QueueFull(9))));

    let snapshot = outbound.snapshot();
    assert_eq!(snapshot.enqueued_messages, 1);
    assert_eq!(snapshot.blocked_sends, 1);
}

#[test]
fn bounded_link_counts_dequeue_and_empty_receive_events() {
    let (outbound, inbound) = bounded_link::<u64>(2);

    assert!(outbound.try_send(11).is_ok());
    assert_eq!(inbound.try_recv().ok().flatten(), Some(11));
    assert_eq!(inbound.try_recv().ok().flatten(), None);

    let snapshot = inbound.snapshot();
    assert_eq!(snapshot.dequeued_messages, 1);
    assert_eq!(snapshot.empty_receives, 1);
}
