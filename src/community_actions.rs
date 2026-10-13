//! Role checks are generated from the action registry before these handlers run.
use crate::{
    api::*,
    error::{Error, Result},
    service::{Context, Door},
};
use cmty::{cplc, cplc::crbk};
use serde_json::Value;

impl Door {
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
            .map_err(|_| Error::Invalid)?;
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
            .map_err(|_| Error::Refused)?;
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
            .map_err(|_| Error::Unavailable)?
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
            .map_err(|_| Error::Refused)?;
        Ok(PinResponse {
            pin: Some(PinView {
                fingerprint: *pin.fingerprint.as_bytes(),
                revision: pin.revision,
            }),
        })
    }
    pub(crate) async fn pin_change(&self, ctx: Context, request: PinChange) -> Result<PinResponse> {
        let community = self.community_backend()?.lock().await;
        let expected = community
            .facade
            .membership()
            .get_pin(ctx.member()?, &request.field)
            .await
            .map_err(|_| Error::Refused)?
            .ok_or(Error::Refused)?;
        let pin = community
            .facade
            .membership()
            .change_pin(
                ctx.member()?,
                &request.field,
                expected,
                &request.pin,
                &request.evidence,
            )
            .await
            .map_err(|_| Error::Refused)?;
        Ok(PinResponse {
            pin: Some(PinView {
                fingerprint: *pin.fingerprint.as_bytes(),
                revision: pin.revision,
            }),
        })
    }
    pub(crate) async fn pin_get(&self, ctx: Context, request: Field) -> Result<PinResponse> {
        let community = self.community_backend()?.lock().await;
        let pin = community
            .facade
            .membership()
            .get_pin(ctx.member()?, &request.field)
            .await
            .map_err(|_| Error::Refused)?;
        Ok(PinResponse {
            pin: pin.map(|p| PinView {
                fingerprint: *p.fingerprint.as_bytes(),
                revision: p.revision,
            }),
        })
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
        community
            .facade
            .policy()
            .lock()
            .await
            .edit_setting(
                &request.key,
                edit,
                ctx.now,
                request.effective_at,
                community.config.minimum_notice_seconds,
            )
            .await
            .map_err(|_| Error::Refused)?;
        community.refresh(ctx.now).await?;
        Ok(community.public.clone())
    }
    pub(crate) async fn schema_check(
        &self,
        _: Context,
        request: SchemaRequest,
    ) -> Result<SchemaChanges> {
        let community = self.community_backend()?.lock().await;
        let policy = community.facade.policy().lock().await;
        let old = policy
            .schema()
            .map_err(|_| Error::Unavailable)?
            .ok_or(Error::Unavailable)?;
        let changes =
            cplc::cshm::classify_changes(old, &request.schema).map_err(|_| Error::Invalid)?;
        Ok(SchemaChanges {
            changes: serde_json::to_value(changes).map_err(|_| Error::Unavailable)?,
        })
    }
    pub(crate) async fn schema_set(
        &self,
        ctx: Context,
        request: SchemaRequest,
    ) -> Result<TrustFeed> {
        let mut community = self.community_backend()?.lock().await;
        community
            .facade
            .policy()
            .lock()
            .await
            .set_schema(request.schema)
            .await
            .map_err(|_| Error::Refused)?;
        community.refresh(ctx.now).await?;
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
    pub(crate) async fn passkey_add(
        &self,
        ctx: Context,
        request: AddPasskey,
    ) -> Result<AddedPasskey> {
        let mut community = self.community_backend()?.lock().await;
        let grant = ctx.grant.as_ref().ok_or(Error::Unauthorized)?;
        let now = self.current_time();
        if now < ctx.now || now >= grant.expires {
            return Err(Error::Unauthorized);
        }
        crate::service::live_time(async {
            let response = community
                .add_passkey(ctx.member()?, grant, request, now)
                .await?;
            let completed = self.current_time();
            if completed < now || completed >= grant.expires {
                return Err(Error::Unauthorized);
            }
            Ok(response)
        })
        .await
    }

    pub(crate) async fn passkey_certificate(&self, ctx: Context, _: Empty) -> Result<Bytes> {
        let community = self.community_backend()?.lock().await;
        let grant = ctx.grant.as_ref().ok_or(Error::Unauthorized)?;
        let now = self.current_time();
        if now < ctx.now || now >= grant.expires {
            return Err(Error::Unauthorized);
        }
        crate::service::live_time(async {
            let certificate = community
                .facade
                .passkey_certificate(ctx.member()?, now)
                .await
                .map_err(|_| Error::Refused)?;
            let completed = self.current_time();
            if completed < now || completed >= grant.expires {
                return Err(Error::Unauthorized);
            }
            Ok(Bytes { bytes: certificate })
        })
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
            .map_err(|_| Error::Refused)?;
        if community
            .facade
            .flush_revocations(ctx.now)
            .await
            .map_err(|_| Error::Unavailable)?
            > 0
        {
            community.refresh(ctx.now).await?;
        }
        let keys = community
            .facade
            .membership()
            .current_device_keys(auth)
            .await
            .map_err(|_| Error::Refused)?;
        Ok(DeviceKeys { keys })
    }

    pub(crate) async fn device_keys(&self, ctx: Context, _: Empty) -> Result<DeviceKeys> {
        let community = self.community_backend()?.lock().await;
        let keys = community
            .facade
            .membership()
            .current_device_keys(ctx.member()?)
            .await
            .map_err(|_| Error::Refused)?;
        Ok(DeviceKeys { keys })
    }

    pub(crate) async fn member_role(&self, ctx: Context, _: Empty) -> Result<MemberRole> {
        let community = self.community_backend()?.lock().await;
        crate::service::live_time(async {
            let lease = community
                .facade
                .membership()
                .role(ctx.member()?)
                .await
                .map_err(|_| Error::Refused)?;
            let now = self.current_time();
            let grant = ctx.grant.as_ref().ok_or(Error::Unauthorized)?;
            if now < ctx.now || now < lease.checked_at() || now >= grant.expires {
                return Err(Error::Unauthorized);
            }
            if now >= lease.valid_until() {
                return Err(Error::Refused);
            }
            Ok(MemberRole {
                member: lease.member().into(),
                role: match lease.role() {
                    cmty::cmbr::Role::Member => Role::Member,
                    cmty::cmbr::Role::Admin => Role::Admin,
                    cmty::cmbr::Role::Root => Role::Root,
                },
            })
        })
        .await
    }

    pub(crate) async fn member_role_set(
        &self,
        ctx: Context,
        request: SetMemberRole,
    ) -> Result<Empty> {
        let community = self.community_backend()?.lock().await;
        let grant = ctx.grant.as_ref().ok_or(Error::Unauthorized)?;
        let now = self.current_time();
        if now < ctx.now || now >= grant.expires {
            return Err(Error::Unauthorized);
        }
        let role = match request.role {
            Role::Member => cmty::cmbr::Role::Member,
            Role::Admin => cmty::cmbr::Role::Admin,
            Role::Root => cmty::cmbr::Role::Root,
        };
        crate::service::live_time(community.facade.membership().set_member_role(
            ctx.member()?,
            &request.member,
            role,
            ctx.now,
            grant.expires,
        ))
        .await
        .map_err(|_| Error::Refused)?;
        Ok(Empty {})
    }

    pub(crate) async fn passkey_revoke(
        &self,
        ctx: Context,
        request: RevokePasskey,
    ) -> Result<Empty> {
        let mut community = self.community_backend()?.lock().await;
        let credential: ckyh::CredentialID = request.credential.into();
        community
            .facade
            .membership()
            .revoke_passkey(ctx.member()?, credential.clone())
            .await
            .map_err(|_| Error::Refused)?;
        community.revoke_sessions(&credential);
        community
            .facade
            .flush_revocations(ctx.now)
            .await
            .map_err(|_| Error::Unavailable)?;
        community.refresh(ctx.now).await?;
        Ok(Empty {})
    }
}
