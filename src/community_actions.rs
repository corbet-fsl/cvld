//! Role checks are generated from the action registry before these handlers run.
use crate::{
    api::*,
    error::{Error, Result},
    service::{Context, Door},
};
use cmty::{cplc, cplc::crbk};
use serde_json::Value;

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
        if !self.is_membership_host(&ctx.host) {
            return self.wallet_passkey_certificate(ctx).await;
        }
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
    pub(crate) async fn device_session_begin(
        &self,
        ctx: Context,
        _: Empty,
    ) -> Result<DeviceSessionChallenge> {
        self.community_backend()?
            .lock()
            .await
            .device_session_begin(ctx.now)
            .await
    }
    pub(crate) async fn device_session_finish(
        &self,
        ctx: Context,
        request: DeviceSessionFinish,
    ) -> Result<Session> {
        self.community_backend()?
            .lock()
            .await
            .device_session_finish(request, ctx.now)
            .await
    }
    pub(crate) async fn garden_session_finish(
        &self,
        ctx: Context,
        request: GardenSessionFinish,
    ) -> Result<Session> {
        if !self.is_garden(&ctx.host) {
            return Err(Error::WrongHost);
        }
        self.community_backend()?
            .lock()
            .await
            .garden_session_finish(request, ctx.now)
            .await
    }
    pub(crate) async fn device_join(
        &self,
        ctx: Context,
        request: DeviceJoin,
    ) -> Result<DeviceJoined> {
        self.community_backend()?
            .lock()
            .await
            .device_join(request, ctx.now)
            .await
    }
    pub(crate) async fn device_add(&self, ctx: Context, request: DevicePairing) -> Result<Empty> {
        self.community_backend()?
            .lock()
            .await
            .device_pairing(crate::device_session::ADD_ACTION, request, ctx.now)
            .await
    }
    pub(crate) async fn device_activate(
        &self,
        ctx: Context,
        request: DevicePairing,
    ) -> Result<Empty> {
        self.community_backend()?
            .lock()
            .await
            .device_pairing(crate::device_session::ACTIVATE_ACTION, request, ctx.now)
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
            .map_err(Error::Refused.redact_at("community_actions.rs:1"))?;
        community.lobby(ctx.member()?, ctx.now).await
    }
    pub(crate) async fn voucher_redeem(
        &self,
        ctx: Context,
        request: VoucherRedeem,
    ) -> Result<Lobby> {
        let community = self.community_backend()?.lock().await;
        community
            .voucher_redeem(ctx.member()?, request, ctx.now)
            .await?;
        community.lobby(ctx.member()?, ctx.now).await
    }
    pub(crate) async fn voucher_link_create(
        &self,
        ctx: Context,
        request: VoucherLinkCreate,
    ) -> Result<VoucherLinkCreated> {
        let community = self.community_backend()?.lock().await;
        community
            .voucher_link_create(ctx.member()?, request, ctx.now)
            .await
    }
    #[cfg(feature = "development-gate")]
    pub(crate) async fn development_voucher_link(
        &self,
        ctx: Context,
        request: VoucherLinkCreate,
    ) -> Result<VoucherLinkCreated> {
        let community = self.community_backend()?.lock().await;
        community
            .development_voucher_link(ctx.member()?, request, ctx.now)
            .await
    }
    pub(crate) async fn voucher_link_view(
        &self,
        _: Context,
        request: VoucherManage,
    ) -> Result<VoucherLinkView> {
        self.community_backend()?
            .lock()
            .await
            .voucher_link_view(request)
            .await
    }
    pub(crate) async fn voucher_signoff_list(
        &self,
        _: Context,
        request: VoucherManage,
    ) -> Result<VoucherSignoffList> {
        self.community_backend()?
            .lock()
            .await
            .voucher_signoff_list(request)
            .await
    }
    pub(crate) async fn voucher_signoff_decide(
        &self,
        _: Context,
        request: VoucherSignoffDecide,
    ) -> Result<VoucherDecision> {
        self.community_backend()?
            .lock()
            .await
            .voucher_signoff_decide(request)
            .await
    }
    pub(crate) async fn voucher_reply_post(
        &self,
        _: Context,
        request: VoucherReplyPost,
    ) -> Result<Empty> {
        self.community_backend()?
            .lock()
            .await
            .voucher_reply_post(request)
            .await?;
        Ok(Empty {})
    }
    pub(crate) async fn voucher_reply_get(
        &self,
        ctx: Context,
        request: VoucherReplyGet,
    ) -> Result<VoucherReply> {
        self.community_backend()?
            .lock()
            .await
            .voucher_reply_get(ctx.member()?, request)
            .await
    }
    pub(crate) async fn voucher_link_revoke(
        &self,
        _: Context,
        request: VoucherManage,
    ) -> Result<VoucherRevoked> {
        self.community_backend()?
            .lock()
            .await
            .voucher_link_revoke(request)
            .await
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
                &ctx,
                request.credential,
                Some((request.gate, request.provider)),
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
            .issue(&ctx, request, None)
            .await
    }
    pub(crate) async fn pin_set(&self, ctx: Context, request: PinRequest) -> Result<PinResponse> {
        let community = self.community_backend()?.lock().await;
        let policy = community.facade.policy().lock().await;
        let schema = policy
            .schema()
            .map_err(Error::Unavailable.redact_at("community_actions.rs:2"))?
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
            .map_err(Error::Refused.redact_at("community_actions.rs:3"))?;
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
            .map_err(Error::Refused.redact_at("community_actions.rs:4"))?;
        Ok(pin_response(pin))
    }
    pub(crate) async fn setting_list(&self, ctx: Context, _: Empty) -> Result<SettingList> {
        self.list_settings(ctx, false).await
    }
    pub(crate) async fn platform_list(&self, ctx: Context, _: Empty) -> Result<SettingList> {
        self.list_settings(ctx, true).await
    }
    /// Read-only; the role was already checked by the registry. Admins can edit
    /// only what the catalogue lets the community layer override and Root has not forced.
    async fn list_settings(&self, ctx: Context, root: bool) -> Result<SettingList> {
        let community = self.community_backend()?.lock().await;
        let book = community
            .facade
            .policy()
            .lock()
            .await
            .rulebook(ctx.now)
            .await
            .map_err(|_| Error::Unavailable)?;
        let views = book.describe().map_err(|_| Error::Unavailable)?;
        let layer = |layer: crbk::Layer| match layer {
            crbk::Layer::Platform => "platform",
            crbk::Layer::Template => "template",
            crbk::Layer::Community => "community",
            crbk::Layer::Member => "member",
        };
        let kind = |t: crbk::SettingType| {
            serde_json::to_value(t)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default()
        };
        let settings = views
            .into_iter()
            .map(|v| {
                let forced = v.platform.as_ref().is_some_and(|p| p.force);
                SettingItem {
                    editable: root || (v.lowest_layer >= crbk::Layer::Community && !forced),
                    key: v.key,
                    group: v.meta.group,
                    label: v.meta.label,
                    help: v.meta.help,
                    unit: v.meta.unit,
                    one_way: v.meta.one_way,
                    value_type: kind(v.value_type),
                    nullable: v.nullable,
                    min: v.min.map(Value::Number),
                    max: v.max.map(Value::Number),
                    lowest_layer: layer(v.lowest_layer).into(),
                    default: v.default,
                    platform: v.platform.map(|p| SettingLayer {
                        value: p.value,
                        force: p.force,
                    }),
                    community: v.community.map(|value| SettingLayer {
                        value,
                        force: false,
                    }),
                    effective: v.effective,
                }
            })
            .collect();
        Ok(SettingList { settings })
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
        // Zero asks for the earliest allowed time, so a client needs no copy of the notice period.
        let effective_at = if request.effective_at == 0 {
            now.saturating_add(community.config.minimum_notice_seconds)
        } else {
            request.effective_at
        };
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
                        effective_at,
                        community.config.minimum_notice_seconds,
                        &mut guard,
                    )
                    .await
                    .map_err(policy_edit_error)?;
            }
            None => {
                policy
                    .edit_setting(
                        &request.key,
                        edit,
                        now,
                        effective_at,
                        community.config.minimum_notice_seconds,
                    )
                    .await
                    .map_err(Error::Refused.redact_at("community_actions.rs:5"))?;
            }
        }
        let completed = self
            .policy_garden_release(&ctx, &community, lease.as_mut())
            .await
            .map_err(Error::Reconcile.redact_at("community_actions.rs:6"))?;
        drop(lease);
        drop(policy);
        community
            .refresh(completed)
            .await
            .map_err(Error::Reconcile.redact_at("community_actions.rs:7"))?;
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
            .map_err(Error::Unavailable.redact_at("community_actions.rs:8"))?
            .ok_or(Error::Unavailable)?;
        let changes =
            cplc::cshm::classify_changes(old, &request.schema).map_err(Error::Invalid.redact())?;
        self.policy_garden_release(&ctx, &community, lease.as_mut())
            .await?;
        Ok(SchemaChanges {
            changes: serde_json::to_value(changes)
                .map_err(Error::Unavailable.redact_at("community_actions.rs:9"))?,
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
                    .map_err(policy_edit_error)?;
            }
            None => {
                policy
                    .set_schema(request.schema)
                    .await
                    .map_err(Error::Refused.redact_at("community_actions.rs:10"))?;
            }
        }
        let completed = self
            .policy_garden_release(&ctx, &community, lease.as_mut())
            .await
            .map_err(Error::Reconcile.redact_at("community_actions.rs:11"))?;
        drop(lease);
        drop(policy);
        community
            .refresh(completed)
            .await
            .map_err(Error::Reconcile.redact_at("community_actions.rs:12"))?;
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
        let authentication = ctx.human_member()?;
        let records = community
            .facade
            .membership()
            .passkeys(authentication)
            .await
            .map_err(Error::Refused.redact_at("community_actions.rs:13"))?;
        Ok(PasskeyList::from_records(
            records,
            authentication.credential_id(),
        ))
    }

    pub(crate) async fn passkey_add(
        &self,
        ctx: Context,
        request: AddPasskeyRequest,
    ) -> Result<AddedPasskey> {
        let request = match request {
            AddPasskeyRequest::Begin { step_up } => {
                self.require_step_up(&ctx, StepUpAction::PasskeyAdd, step_up.map(|proof| *proof))
                    .await?;
                AddPasskey::Begin
            }
            AddPasskeyRequest::Finish {
                ceremony,
                credential,
            } => AddPasskey::Finish {
                ceremony,
                credential,
            },
        };
        if !self.is_membership_host(&ctx.host) {
            if self.service_scope() == Scope::Global
                && ctx
                    .grant
                    .as_ref()
                    .is_some_and(|grant| grant.role == Role::Member)
            {
                return self.wallet_add_passkey(ctx, request).await;
            }
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
                ctx.human_member()?,
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
        let DeviceKey {
            key,
            step_up,
            birth_signature,
        } = request;
        // The birth bind exists only for the wallet.
        if birth_signature.is_some() {
            return Err(Error::Invalid);
        }
        self.require_step_up(&ctx, StepUpAction::DeviceAuthorize { key }, step_up)
            .await?;
        let mut community = self.community_backend()?.lock().await;
        let auth = ctx.human_member()?;
        community
            .facade
            .membership()
            .authorize_device_key(auth, key)
            .await
            .map_err(Error::Refused.redact_at("community_actions.rs:14"))?;
        if community
            .facade
            .flush_revocations(ctx.now)
            .await
            .map_err(Error::Unavailable.redact_at("community_actions.rs:15"))?
            > 0
        {
            community.refresh(ctx.now).await?;
        }
        let keys = community
            .facade
            .membership()
            .current_device_keys(auth)
            .await
            .map_err(Error::Refused.redact_at("community_actions.rs:16"))?;
        Ok(DeviceKeys { keys })
    }

    /// Pairing: bind the new device's key to the new device's own passkey as PENDING. It
    /// grants nothing (the answer lists only live keys) and expires unless confirmed.
    pub(crate) async fn device_pair_authorize(
        &self,
        ctx: Context,
        request: DeviceKey,
    ) -> Result<DeviceKeys> {
        let DeviceKey {
            key,
            step_up,
            birth_signature,
        } = request;
        // The birth bind exists only for the wallet.
        if birth_signature.is_some() {
            return Err(Error::Invalid);
        }
        self.require_step_up(&ctx, StepUpAction::DeviceAuthorize { key }, step_up)
            .await?;
        let community = self.community_backend()?.lock().await;
        let auth = ctx.human_member()?;
        let membership = community.facade.membership();
        membership
            .authorize_pending_device_key(auth, key)
            .await
            .map_err(Error::Refused.redact_at("community_actions.rs:17"))?;
        let keys = membership
            .current_device_keys(auth)
            .await
            .map_err(Error::Refused.redact_at("community_actions.rs:18"))?;
        Ok(DeviceKeys { keys })
    }

    /// Pairing: the existing device approves a pending key, with a fresh step-up for that
    /// exact key, after publishing the lineage revision that contains it.
    pub(crate) async fn device_approve(
        &self,
        ctx: Context,
        request: DeviceApprove,
    ) -> Result<DeviceKeys> {
        let DeviceApprove { key, step_up } = request;
        self.require_step_up(&ctx, StepUpAction::DeviceApprove { key }, step_up)
            .await?;
        let community = self.community_backend()?.lock().await;
        let auth = ctx.human_member()?;
        let membership = community.facade.membership();
        membership
            .approve_pending_device_key(auth, key)
            .await
            .map_err(Error::Refused.redact_at("community_actions.rs:19"))?;
        let keys = membership
            .current_device_keys(auth)
            .await
            .map_err(Error::Refused.redact_at("community_actions.rs:20"))?;
        Ok(DeviceKeys { keys })
    }

    /// Pairing: make this passkey's pending key live once its lineage revision is published.
    pub(crate) async fn device_confirm(
        &self,
        ctx: Context,
        request: DeviceConfirm,
    ) -> Result<DeviceKeys> {
        let community = self.community_backend()?.lock().await;
        let auth = ctx.human_member()?;
        let membership = community.facade.membership();
        membership
            .confirm_device_key(auth, request.key)
            .await
            .map_err(Error::Refused.redact_at("community_actions.rs:21"))?;
        let keys = membership
            .current_device_keys(auth)
            .await
            .map_err(Error::Refused.redact_at("community_actions.rs:22"))?;
        Ok(DeviceKeys { keys })
    }

    /// Remove a device key (a lost device), live or pending, behind a fresh step-up.
    pub(crate) async fn device_revoke(
        &self,
        ctx: Context,
        request: DeviceRevoke,
    ) -> Result<DeviceKeys> {
        let DeviceRevoke { key, step_up } = request;
        self.require_step_up(&ctx, StepUpAction::DeviceRevoke { key }, step_up)
            .await?;
        let mut community = self.community_backend()?.lock().await;
        let auth = ctx.human_member()?;
        community
            .facade
            .membership()
            .revoke_device_key(auth, key)
            .await
            .map_err(Error::Refused.redact_at("community_actions.rs:23"))?;
        if community
            .facade
            .flush_revocations(ctx.now)
            .await
            .map_err(Error::Unavailable.redact_at("community_actions.rs:24"))?
            > 0
        {
            community.refresh(ctx.now).await?;
        }
        let keys = community
            .facade
            .membership()
            .current_device_keys(auth)
            .await
            .map_err(Error::Refused.redact_membership_at("community_actions.rs:25"))?;
        Ok(DeviceKeys { keys })
    }

    pub(crate) async fn device_keys(&self, ctx: Context, _: Empty) -> Result<DeviceKeys> {
        let community = self.community_backend()?.lock().await;
        let keys = community
            .facade
            .membership()
            .current_device_keys(ctx.member()?)
            .await
            .map_err(Error::Refused.redact_membership_at("community_actions.rs:26"))?;
        Ok(DeviceKeys { keys })
    }

    pub(crate) async fn passkey_revoke(
        &self,
        ctx: Context,
        request: RevokePasskey,
    ) -> Result<Empty> {
        let RevokePasskey {
            credential,
            step_up,
        } = request;
        self.require_step_up(
            &ctx,
            StepUpAction::PasskeyRevoke {
                credential: credential.clone(),
            },
            step_up,
        )
        .await?;
        if !self.is_membership_host(&ctx.host) {
            if self.service_scope() == Scope::Global
                && ctx
                    .grant
                    .as_ref()
                    .is_some_and(|grant| grant.role == Role::Member)
            {
                return self.wallet_revoke_passkey(ctx, credential).await;
            }
            self.auth(&ctx.host)?
                .lock()
                .await
                .revoke_passkey(
                    ctx.token.as_deref().ok_or(Error::Unauthorized)?,
                    credential.into(),
                    ctx.now,
                )
                .await?;
            return Ok(Empty {});
        }
        let mut community = self.community_backend()?.lock().await;
        let credential: ckyh::CredentialID = credential.into();
        community
            .facade
            .membership()
            .revoke_passkey(ctx.human_member()?, credential.clone())
            .await
            .map_err(Error::Refused.redact_at("community_actions.rs:27"))?;
        community.revoke_sessions(&credential);
        community
            .facade
            .flush_revocations(ctx.now)
            .await
            .map_err(Error::Unavailable.redact_at("community_actions.rs:28"))?;
        community.refresh(ctx.now).await?;
        Ok(Empty {})
    }
}

/// A rejected policy edit changed nothing and is a refusal. Only an unknown
/// storage or signing outcome, or corrupt stored state, is uncertain.
fn policy_edit_error(error: cmty::cplc::Error) -> Error {
    use cmty::cplc::Error as Policy;
    match error {
        Policy::Storage
        | Policy::ReloadRequired
        | Policy::Signing
        | Policy::Corrupt
        | Policy::Verification => Error::Reconcile,
        Policy::Denied(_) | Policy::Revoked => Error::Forbidden,
        Policy::Invalid(_)
        | Policy::Missing
        | Policy::Conflict
        | Policy::Rulebook
        | Policy::Schema => Error::Refused,
    }
}
