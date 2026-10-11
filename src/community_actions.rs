//! Role checks are generated from the action registry before these handlers run.
use crate::{
    api::*,
    error::{Error, Result},
    service::{Context, Door},
};
use cmty::{cplc, cplc::crbk};

fn pin_response(pin: Option<cmty::cmbr::Pin>) -> PinResponse {
    PinResponse {
        pin: pin.map(|pin| PinView {
            fingerprint: *pin.fingerprint.as_bytes(),
            revision: pin.revision,
        }),
    }
}

impl Door {
    pub(crate) async fn community_self_ban_status_begin(
        &self,
        ctx: Context,
        _: Empty,
    ) -> Result<SelfBanStatusChallenge> {
        if !self.is_community_member(&ctx.host) {
            return Err(Error::WrongHost);
        }
        self.community_backend()?
            .lock()
            .await
            .self_ban_status_begin(ctx.now)
            .await
    }
    pub(crate) async fn community_self_ban_status_finish(
        &self,
        ctx: Context,
        request: SelfBanConfirmation,
    ) -> Result<SelfBanStatus> {
        if !self.is_community_member(&ctx.host) {
            return Err(Error::WrongHost);
        }
        self.community_backend()?
            .lock()
            .await
            .self_ban_status_finish(request, ctx.now)
            .await
    }
    pub(crate) async fn passkey_certificate(
        &self,
        ctx: Context,
        _: Empty,
    ) -> Result<PasskeyCertificateResponse> {
        self.community_backend()?
            .lock()
            .await
            .certificate(ctx.token.as_deref().ok_or(Error::Unauthorized)?, ctx.now)
            .await
    }
    pub(crate) async fn community_self_ban_begin(
        &self,
        ctx: Context,
        _: Empty,
    ) -> Result<SelfBanChallenge> {
        self.community_backend()?
            .lock()
            .await
            .self_ban_begin(ctx.token.as_deref().ok_or(Error::Unauthorized)?, ctx.now)
            .await
    }
    pub(crate) async fn community_self_ban_finish(
        &self,
        ctx: Context,
        request: SelfBanConfirmation,
    ) -> Result<Empty> {
        self.community_backend()?
            .lock()
            .await
            .self_ban_finish(
                ctx.token.as_deref().ok_or(Error::Unauthorized)?,
                request,
                ctx.now,
            )
            .await?;
        Ok(Empty {})
    }
    pub(crate) async fn presentation_challenge(
        &self,
        ctx: Context,
        _: Empty,
    ) -> Result<PresentationChallenge> {
        self.community_backend()?
            .lock()
            .await
            .challenge(ctx.grant.as_ref().map(|g| g.user), ctx.now)
            .await
    }
    pub(crate) async fn lobby(&self, ctx: Context, _: Empty) -> Result<Lobby> {
        self.community_backend()?
            .lock()
            .await
            .lobby(ctx.member()?, ctx.now)
            .await
    }
    pub(crate) async fn handle_available(
        &self,
        ctx: Context,
        request: Handle,
    ) -> Result<Available> {
        let community = self.community_backend()?.lock().await;
        let reserved = community.reserved(ctx.now).await?;
        let available = community
            .facade
            .membership()
            .is_handle_available(&request.handle, &reserved)
            .await
            .map_err(Error::Invalid.redact())?;
        Ok(Available { available })
    }
    pub(crate) async fn handle_reserve(&self, ctx: Context, request: Handle) -> Result<Lobby> {
        let community = self.community_backend()?.lock().await;
        let reserved = community.reserved(ctx.now).await?;
        community
            .facade
            .membership()
            .reserve_handle(ctx.member()?, &request.handle, &reserved)
            .await
            .map_err(Error::Refused.redact())?;
        community.lobby(ctx.member()?, ctx.now).await
    }
    pub(crate) async fn gate_voucher(&self, ctx: Context, request: Voucher) -> Result<Lobby> {
        let community = self.community_backend()?.lock().await;
        community.voucher(ctx.member()?, request, ctx.now).await?;
        community.lobby(ctx.member()?, ctx.now).await
    }
    pub(crate) async fn gate_withdraw(
        &self,
        ctx: Context,
        request: Withdraw,
    ) -> Result<CredentialResponse> {
        self.community_backend()?
            .lock()
            .await
            .issue(
                ctx.member()?,
                request.credential,
                Some((request.gate, request.provider)),
                ctx.now,
            )
            .await
    }
    pub(crate) async fn credential_issue(
        &self,
        ctx: Context,
        request: CredentialRequest,
    ) -> Result<CredentialResponse> {
        self.community_backend()?
            .lock()
            .await
            .issue(ctx.member()?, request, None, ctx.now)
            .await
    }
    pub(crate) async fn pin_set(&self, ctx: Context, request: PinRequest) -> Result<PinResponse> {
        let community = self.community_backend()?.lock().await;
        let policy = community.facade.policy().lock().await;
        let schema = policy
            .schema()
            .map_err(Error::Unavailable.redact())?
            .ok_or(Error::Unavailable)?;
        if !schema
            .public
            .iter()
            .chain(&schema.private)
            .any(|f| f.id == request.field && f.change_preset != cplc::cshm::ChangePreset::Free)
        {
            return Err(Error::Invalid);
        }
        drop(policy);
        let pin = community
            .facade
            .membership()
            .pin(ctx.member()?, &request.field, &request.pin)
            .await
            .map_err(Error::Refused.redact())?;
        Ok(pin_response(Some(pin)))
    }
    pub(crate) async fn pin_change(&self, ctx: Context, request: PinChange) -> Result<PinResponse> {
        if !self.is_community_member(&ctx.host) {
            return Err(Error::WrongHost);
        }
        let community = self.community_backend()?.lock().await;
        community
            .change_native_pin(
                ctx.token.as_deref().ok_or(Error::Unauthorized)?,
                request,
                ctx.now,
            )
            .await
            .map(Some)
            .map(pin_response)
    }
    pub(crate) async fn pin_get(&self, ctx: Context, request: Field) -> Result<PinResponse> {
        let community = self.community_backend()?.lock().await;
        let pin = community
            .facade
            .membership()
            .get_pin(ctx.member()?, &request.field)
            .await
            .map_err(Error::Refused.redact())?;
        Ok(pin_response(pin))
    }
    pub(crate) async fn setting_set(&self, ctx: Context, request: Setting) -> Result<TrustFeed> {
        self.edit_setting(ctx, request, None).await
    }
    pub(crate) async fn platform_set(
        &self,
        ctx: Context,
        request: PlatformSetting,
    ) -> Result<TrustFeed> {
        self.edit_setting(ctx, request.setting, Some(request.force))
            .await
    }
    async fn edit_setting(
        &self,
        ctx: Context,
        request: Setting,
        force: Option<bool>,
    ) -> Result<TrustFeed> {
        let mut community = self.community_backend()?.lock().await;
        let edit = match force {
            Some(force) => {
                cplc::SettingEdit::Platform((!request.inherit).then_some(crbk::PlatformValue {
                    value: request.value,
                    force,
                }))
            }
            None => cplc::SettingEdit::Community((!request.inherit).then_some(request.value)),
        };
        let mut policy = community.facade.policy().lock().await;
        let mut lease = self.policy_garden_lease(&ctx, &community).await?;
        let now = self
            .policy_garden_release(&ctx, &community, lease.as_mut())
            .await?;
        match lease.as_mut() {
            Some(lease) => {
                let mut guard = crate::community::garden::GardenCommit::new(
                    &community,
                    &ctx,
                    lease,
                    "setting_set",
                );
                policy
                    .edit_setting_checked(
                        &request.key,
                        edit,
                        now,
                        request.effective_at,
                        community.config.minimum_notice_seconds,
                        &mut guard,
                    )
                    .await
                    .map_err(Error::Reconcile.redact())?;
            }
            None => {
                policy
                    .edit_setting(
                        &request.key,
                        edit,
                        now,
                        request.effective_at,
                        community.config.minimum_notice_seconds,
                    )
                    .await
                    .map_err(Error::Refused.redact())?;
            }
        }
        let completed = self
            .policy_garden_release(&ctx, &community, lease.as_mut())
            .await
            .map_err(Error::Reconcile.redact())?;
        drop(lease);
        drop(policy);
        community
            .refresh(completed)
            .await
            .map_err(Error::Reconcile.redact())?;
        Ok(community.public.clone())
    }
    pub(crate) async fn schema_check(
        &self,
        ctx: Context,
        request: SchemaRequest,
    ) -> Result<SchemaChanges> {
        let community = self.community_backend()?.lock().await;
        let policy = community.facade.policy().lock().await;
        let mut lease = self.policy_garden_lease(&ctx, &community).await?;
        self.policy_garden_release(&ctx, &community, lease.as_mut())
            .await?;
        let old = policy
            .schema()
            .map_err(Error::Unavailable.redact())?
            .ok_or(Error::Unavailable)?;
        let changes =
            cplc::cshm::classify_changes(old, &request.schema).map_err(Error::Invalid.redact())?;
        self.policy_garden_release(&ctx, &community, lease.as_mut())
            .await?;
        Ok(SchemaChanges {
            changes: serde_json::to_value(changes).map_err(Error::Unavailable.redact())?,
        })
    }
    pub(crate) async fn schema_set(
        &self,
        ctx: Context,
        request: SchemaRequest,
    ) -> Result<TrustFeed> {
        let mut community = self.community_backend()?.lock().await;
        let mut policy = community.facade.policy().lock().await;
        let mut lease = self.policy_garden_lease(&ctx, &community).await?;
        self.policy_garden_release(&ctx, &community, lease.as_mut())
            .await?;
        match lease.as_mut() {
            Some(lease) => {
                let mut guard = crate::community::garden::GardenCommit::new(
                    &community,
                    &ctx,
                    lease,
                    "schema_set",
                );
                policy
                    .set_schema_checked(request.schema, &mut guard)
                    .await
                    .map_err(Error::Reconcile.redact())?;
            }
            None => {
                policy
                    .set_schema(request.schema)
                    .await
                    .map_err(Error::Refused.redact())?;
            }
        }
        let completed = self
            .policy_garden_release(&ctx, &community, lease.as_mut())
            .await
            .map_err(Error::Reconcile.redact())?;
        drop(lease);
        drop(policy);
        community
            .refresh(completed)
            .await
            .map_err(Error::Reconcile.redact())?;
        Ok(community.public.clone())
    }
    pub(crate) async fn trust_feed(&self, _: Context, _: Empty) -> Result<TrustFeed> {
        Ok(self.community_public()?.borrow().as_ref().clone())
    }
    pub(crate) async fn trust_changes(&self, _: Context, request: Since) -> Result<Announcement> {
        let mut changes = self.community_public()?;
        if changes.borrow_and_update().revision <= request.revision {
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(25), changes.changed()).await;
        }
        let public = changes.borrow();
        let (revision, policy_epoch) = (public.revision, public.policy_epoch);
        Ok(Announcement {
            revision,
            policy_epoch,
            changed: revision > request.revision,
        })
    }
    pub(crate) async fn passkey_list(&self, ctx: Context, _: Empty) -> Result<PasskeyList> {
        if !self.is_membership_host(&ctx.host) {
            return self
                .auth(&ctx.host)?
                .lock()
                .await
                .list_passkeys(ctx.token.as_deref().ok_or(Error::Unauthorized)?, ctx.now)
                .await;
        }
        let community = self.community_backend()?.lock().await;
        let authentication = ctx.member()?;
        let records = community
            .facade
            .membership()
            .passkeys(authentication)
            .await
            .map_err(Error::Refused.redact())?;
        Ok(PasskeyList::from_records(
            records,
            authentication.credential_id(),
        ))
    }

    pub(crate) async fn passkey_add(
        &self,
        ctx: Context,
        request: AddPasskey,
    ) -> Result<AddedPasskey> {
        if !self.is_membership_host(&ctx.host) {
            return self
                .auth(&ctx.host)?
                .lock()
                .await
                .add_passkey(
                    ctx.token.as_deref().ok_or(Error::Unauthorized)?,
                    request,
                    ctx.now,
                )
                .await;
        }
        self.community_backend()?
            .lock()
            .await
            .add_passkey(
                ctx.member()?,
                ctx.grant.as_ref().ok_or(Error::Unauthorized)?,
                request,
                ctx.now,
            )
            .await
    }

    pub(crate) async fn device_authorize(
        &self,
        ctx: Context,
        request: DeviceKey,
    ) -> Result<DeviceKeys> {
        let mut community = self.community_backend()?.lock().await;
        let auth = ctx.member()?;
        community
            .facade
            .membership()
            .authorize_device_key(auth, request.key)
            .await
            .map_err(Error::Refused.redact())?;
        if community
            .facade
            .flush_revocations(ctx.now)
            .await
            .map_err(Error::Unavailable.redact())?
            > 0
        {
            community.refresh(ctx.now).await?;
        }
        let keys = community
            .facade
            .membership()
            .current_device_keys(auth)
            .await
            .map_err(Error::Refused.redact())?;
        Ok(DeviceKeys { keys })
    }

    pub(crate) async fn device_keys(&self, ctx: Context, _: Empty) -> Result<DeviceKeys> {
        let community = self.community_backend()?.lock().await;
        let keys = community
            .facade
            .membership()
            .current_device_keys(ctx.member()?)
            .await
            .map_err(Error::Refused.redact())?;
        Ok(DeviceKeys { keys })
    }

    pub(crate) async fn passkey_revoke(
        &self,
        ctx: Context,
        request: RevokePasskey,
    ) -> Result<Empty> {
        if !self.is_membership_host(&ctx.host) {
            self.auth(&ctx.host)?
                .lock()
                .await
                .revoke_passkey(
                    ctx.token.as_deref().ok_or(Error::Unauthorized)?,
                    request.credential.into(),
                    ctx.now,
                )
                .await?;
            return Ok(Empty {});
        }
        let mut community = self.community_backend()?.lock().await;
        let credential: ckyh::CredentialID = request.credential.into();
        community
            .facade
            .membership()
            .revoke_passkey(ctx.member()?, credential.clone())
            .await
            .map_err(Error::Refused.redact())?;
        community.revoke_sessions(&credential);
        community
            .facade
            .flush_revocations(ctx.now)
            .await
            .map_err(Error::Unavailable.redact())?;
        community.refresh(ctx.now).await?;
        Ok(Empty {})
    }
}
