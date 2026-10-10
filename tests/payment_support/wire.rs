//! Inert original x402 protocol boundary; no application logic is replaced.
use super::*;

pub enum Reply {
    Success,
    Unknown,
    PauseBeforeSupported,
    PauseAfterSettle,
}
pub struct Wire {
    pub reply: Reply,
    pub supported: AtomicUsize,
    pub verified: AtomicUsize,
    pub settled: AtomicUsize,
    pub entered: tokio::sync::Notify,
    pub release: tokio::sync::Notify,
}
impl Wire {
    pub fn new(reply: Reply) -> Arc<Self> {
        Arc::new(Self {
            reply,
            supported: AtomicUsize::new(0),
            verified: AtomicUsize::new(0),
            settled: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        })
    }
}
pub struct Inert(pub Arc<Wire>);
fn exchange<T>(value: T) -> Exchange<T> {
    Exchange {
        result: Ok(value),
        upstream: vec![],
    }
}
impl Transport for Inert {
    async fn supported_details(&self, guard: &DispatchGuard<'_>) -> Exchange<SupportedResponse> {
        if let Err(error) = guard.check() {
            return Exchange {
                result: Err(error),
                upstream: vec![],
            };
        }
        if matches!(self.0.reply, Reply::PauseBeforeSupported) {
            self.0.entered.notify_one();
            self.0.release.notified().await;
        }
        if let Err(error) = guard.check() {
            return Exchange {
                result: Err(error),
                upstream: vec![],
            };
        }
        self.0.supported.fetch_add(1, Ordering::SeqCst);
        exchange(SupportedResponse {
            kinds: vec![SupportedPaymentKind {
                x402_version: 2,
                scheme: "exact".into(),
                network: "eip155:8453".into(),
                extra: None,
            }],
            ..Default::default()
        })
    }
    async fn verify_details(
        &self,
        _: &VerifyRequest,
        guard: &DispatchGuard<'_>,
    ) -> Exchange<VerifyResponse> {
        if let Err(error) = guard.check() {
            return Exchange {
                result: Err(error),
                upstream: vec![],
            };
        }
        self.0.verified.fetch_add(1, Ordering::SeqCst);
        exchange(VerifyResponse(
            json!({"isValid":true,"payer":"PRIVATE-PAYER"}),
        ))
    }
    async fn settle_details(
        &self,
        _: &SettleRequest,
        guard: &DispatchGuard<'_>,
    ) -> Exchange<SettleResponse> {
        if let Err(error) = guard.check() {
            return Exchange {
                result: Err(error),
                upstream: vec![],
            };
        }
        self.0.settled.fetch_add(1, Ordering::SeqCst);
        if matches!(self.0.reply, Reply::PauseAfterSettle) {
            self.0.entered.notify_one();
            self.0.release.notified().await;
        }
        if matches!(self.0.reply, Reply::Unknown) {
            Exchange {
                result: Err(cpmt::payments::Error::Rejected),
                upstream: vec![],
            }
        } else {
            exchange(SettleResponse(
                json!({"success":true,"network":"eip155:8453","transaction":"PRIVATE-CHAIN-TRANSACTION","payer":"PRIVATE-PAYER","KYC":"PRIVATE-KYC"}),
            ))
        }
    }
}
