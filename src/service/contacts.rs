//! Thin contact action composition. Leaves authenticate; cgbl owns gate policy.
use super::*;
use crate::contact_gates::{self, Constraints, Owner};
use std::collections::BTreeSet;

fn contact_error(error: contact_gates::Error) -> Error {
    match error {
        contact_gates::Error::Input | contact_gates::Error::Configuration => Error::Invalid,
        contact_gates::Error::Capacity => Error::Throttled,
        contact_gates::Error::Storage => Error::Unavailable,
        contact_gates::Error::Migration => Error::Refused,
        contact_gates::Error::Uncertain => Error::Reconcile,
        _ => Error::Refused,
    }
}
impl Context {
    fn contact_owner(&self) -> Result<Owner> {
        Ok(Owner {
            subject: self.subject()?,
            session: self.grant.as_ref().ok_or(Error::Unauthorized)?.session_id,
        })
    }
}
impl Door {
    pub(crate) async fn contact_plan(
        &self,
        ctx: Context,
        request: ContactPlan,
    ) -> Result<ContactPreview> {
        let owner = ctx.contact_owner()?;
        let mut global = self.global_backend()?.lock().await;
        let now = self.current_time(&ctx)?;
        let limit = global.contact_ceremony_seconds.ok_or(Error::Refused)?;
        let session_expires = ctx.grant.as_ref().ok_or(Error::Unauthorized)?.expires;
        let pending_expires_at = now
            .checked_add(limit)
            .ok_or(Error::Invalid)?
            .min(session_expires);
        let check = cgbl::CheckId::generate(&mut cpsd::rand::rngs::OsRng);
        let mut seen = BTreeSet::new();
        let mut selections = Vec::new();
        let mut fact_expires_at = None;
        for option in request.options {
            if !seen.insert(option.clone()) {
                return Err(Error::Invalid);
            }
            let (_, provider, channel) = global
                .contacts
                .as_ref()
                .ok_or(Error::Refused)?
                .providers()
                .find(|(id, _, _)| *id == option)
                .ok_or(Error::Refused)?;
            let authorization = global
                .facade
                .authorize_contact(channel.gate(), provider, &owner.subject, &check, &|| {
                    self.inner.clock.now()
                })
                .await
                .map_err(Error::Refused.redact())?;
            let expires = authorization.fact_expires_at();
            if fact_expires_at
                .replace(expires)
                .is_some_and(|prior| prior != expires)
            {
                return Err(Error::Refused);
            }
            selections.push((option, authorization.binding().clone()));
        }
        let fact_expires_at = fact_expires_at.ok_or(Error::Invalid)?;
        let pending_expires_at = pending_expires_at.min(fact_expires_at);
        self.current_time(&ctx)?;
        global
            .contacts
            .as_mut()
            .ok_or(Error::Refused)?
            .prepare_begin(
                owner,
                selections,
                &request.destination,
                Constraints {
                    check,
                    budget: request.budget,
                    max_attempts: request.max_attempts,
                    order: request.order,
                    pending_expires_at,
                    fact_expires_at,
                },
            )
            .map_err(contact_error)
    }
    pub(crate) async fn contact_check(
        &self,
        ctx: Context,
        request: ContactCheck,
    ) -> Result<ContactPreview> {
        let owner = ctx.contact_owner()?;
        let mut global = self.global_backend()?.lock().await;
        self.current_time(&ctx)?;
        global
            .contacts
            .as_mut()
            .ok_or(Error::Refused)?
            .prepare_check(&request.operation, &owner, &request.code)
            .map_err(contact_error)
    }
    pub(crate) async fn contact_execute(
        &self,
        ctx: Context,
        request: ContactExecute,
    ) -> Result<ContactReceipt> {
        let owner = ctx.contact_owner()?;
        let mut global = self.global_backend()?.lock().await;
        self.current_time(&ctx)?;
        let contacts = global.contacts.as_ref().ok_or(Error::Refused)?;
        let (options, expected_expiry) = contacts
            .execution_context(&request.operation, &owner)
            .map_err(contact_error)?;
        let check = contacts
            .check(&request.operation, &owner)
            .map_err(contact_error)?
            .clone();
        let selected: Vec<_> = options
            .iter()
            .map(|option| {
                contacts
                    .providers()
                    .find(|(id, _, _)| *id == option.as_str())
                    .map(|(_, provider, channel)| (provider.to_owned(), channel))
            })
            .collect::<Option<_>>()
            .ok_or(Error::Refused)?;
        let token = ctx.token.as_ref().ok_or(Error::Unauthorized)?.clone();
        let auth = self.auth(&ctx.host)?;
        let clock = self.inner.clock.clone();
        let crate::global::GlobalService {
            facade, contacts, ..
        } = &mut *global;
        let facade = &*facade;
        let verify = || -> std::pin::Pin<Box<dyn std::future::Future<Output = contact_gates::Result<u64>> + Send + '_>> {
            Box::pin(async {
                let now = clock.now();
                if now < ctx.now || now >= ctx.grant.as_ref().ok_or(contact_gates::Error::Refused)?.expires { return Err(contact_gates::Error::Refused); }
                let mut observed = now;
                for (provider, channel) in &selected {
                    let authorized = facade.authorize_contact(channel.gate(), provider, &owner.subject, &check, &|| clock.now()).await.map_err(|_| contact_gates::Error::Refused)?;
                    if authorized.fact_expires_at() != expected_expiry || authorized.observed_at() < observed { return Err(contact_gates::Error::Refused); }
                    observed = authorized.observed_at();
                }
                let authentication_at = clock.now();
                if authentication_at < observed { return Err(contact_gates::Error::Refused); }
                let grant = auth.lock().await.authenticate(&token, authentication_at).await.map_err(|_| contact_gates::Error::Refused)?;
                if grant.user.to_string() != owner.subject.as_str() || grant.session_id != owner.session || grant.role != Role::Member { return Err(contact_gates::Error::Refused); }
                let completed = clock.now();
                if completed < authentication_at || completed >= grant.expires { return Err(contact_gates::Error::Refused); }
                Ok(completed)
            })
        };
        contacts
            .as_mut()
            .ok_or(Error::Refused)?
            .execute_checked(&request.operation, &request.authorization, &owner, &verify)
            .await
            .map_err(contact_error)
    }
    pub(crate) async fn contact_status(
        &self,
        ctx: Context,
        request: ContactOperation,
    ) -> Result<ContactReceipt> {
        let owner = ctx.contact_owner()?;
        let global = self.global_backend()?.lock().await;
        self.current_time(&ctx)?;
        global
            .contacts
            .as_ref()
            .ok_or(Error::Refused)?
            .status(&request.operation, &owner)
            .await
            .map_err(contact_error)
    }
    pub(crate) async fn contact_accept(
        &self,
        ctx: Context,
        request: ContactOperation,
    ) -> Result<ContactAcceptance> {
        let owner = ctx.contact_owner()?;
        let global = self.global_backend()?.lock().await;
        let now = self.current_time(&ctx)?;
        let contacts = global.contacts.as_ref().ok_or(Error::Refused)?;
        let gate = contacts
            .gate(&request.operation, &owner)
            .map_err(contact_error)?;
        let check = contacts
            .check(&request.operation, &owner)
            .map_err(contact_error)?;
        let accepted = global
            .facade
            .run_gate(gate, &owner.subject, gate.input(), now, check)
            .await
            .map_err(Error::Refused.redact())?;
        Ok(ContactAcceptance {
            gate: accepted.gate,
            provider: accepted.provider,
            valid_until: accepted.valid_until,
        })
    }
    pub(crate) async fn contact_simulate(
        &self,
        ctx: Context,
        request: ContactSimulationRequest,
    ) -> Result<ContactSimulationResponse> {
        let now = self.current_time(&ctx)?;
        contact_gates::simulation::simulate(request, b"global.contact.simulation", now)
            .map_err(contact_error)
    }
}
