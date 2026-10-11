//! The actual wallet Auth and Global owners, held through final output checks.
use super::*;

impl Door {
    pub(crate) async fn wallet_passkey_certificate(
        &self,
        ctx: Context,
    ) -> Result<PasskeyCertificateResponse> {
        with_live_clock(async {
            let token = ctx.token.as_deref().ok_or(Error::Unauthorized)?;
            let authentication = self.auth(&ctx.host)?;
            let mut auth = authentication.lock().await;
            let mut session = auth
                .wallet_session(
                    token,
                    ctx.grant.as_ref().ok_or(Error::Unauthorized)?,
                    ctx.now,
                    self.inner.clock.as_ref(),
                )
                .await?;
            let mut global = self.global_backend()?.lock().await;
            session
                .check(&mut auth, token, ctx.now, self.inner.clock.as_ref())
                .await?;
            let issued = global
                .wallet_certificate(&session, self.inner.clock.as_ref())
                .await?;
            let completed = session
                .check(
                    &mut auth,
                    token,
                    issued.checked_at(),
                    self.inner.clock.as_ref(),
                )
                .await?;
            let returned_at =
                session.check_sync(&auth, token, completed, self.inner.clock.as_ref())?;
            global
                .wallet
                .as_ref()
                .ok_or(Error::Forbidden)?
                .key_ring()
                .map_err(Error::Refused.redact())?
                .verify(issued.bytes(), csgn::Kind::Credential, returned_at)
                .map_err(Error::Refused.redact())?;
            // No await follows the same-session/current-key/lifetime check.
            Ok(PasskeyCertificateResponse {
                bytes: issued.into_bytes(),
                checked_at: returned_at,
            })
        })
        .await
    }
    pub(crate) async fn wallet_device_keys(&self, ctx: Context, _: Empty) -> Result<DeviceKeys> {
        self.wallet_device_observation(ctx, None).await
    }
    pub(crate) async fn wallet_device_authorize(
        &self,
        ctx: Context,
        request: DeviceKey,
    ) -> Result<DeviceKeys> {
        self.wallet_device_observation(ctx, Some(request.key)).await
    }
    async fn wallet_device_observation(
        &self,
        ctx: Context,
        device: Option<[u8; 32]>,
    ) -> Result<DeviceKeys> {
        let token = ctx.token.as_deref().ok_or(Error::Unauthorized)?;
        let authentication = self.auth(&ctx.host)?;
        let mut auth = authentication.lock().await;
        let mut session = auth
            .wallet_session(
                token,
                ctx.grant.as_ref().ok_or(Error::Unauthorized)?,
                ctx.now,
                self.inner.clock.as_ref(),
            )
            .await?;
        let mut global = self.global_backend()?.lock().await;
        session
            .check(&mut auth, token, ctx.now, self.inner.clock.as_ref())
            .await?;
        let observation = global
            .wallet_devices(&session, device, self.inner.clock.as_ref())
            .await?;
        let finish = async {
            let completed = session
                .check(
                    &mut auth,
                    token,
                    observation.checked_at(),
                    self.inner.clock.as_ref(),
                )
                .await?;
            if observation.member() != session.member()?.member().to_string() {
                return Err(Error::Unauthorized);
            }
            if device.is_some() {
                global.publish_wallet(completed).await?;
            }
            let completed = session
                .check(&mut auth, token, completed, self.inner.clock.as_ref())
                .await?;
            session.check_sync(&auth, token, completed, self.inner.clock.as_ref())?;
            Ok(DeviceKeys {
                keys: observation.devices().to_vec(),
            })
        }
        .await;
        finish.map_err(|error| {
            if device.is_some() {
                Error::Reconcile
            } else {
                error
            }
        })
    }
    pub(crate) async fn wallet_trust_feed(&self, ctx: Context, _: Empty) -> Result<TrustFeed> {
        let mut global = self.global_backend()?.lock().await;
        let now = self.inner.clock.now();
        if now < ctx.now {
            return Err(Error::Unavailable);
        }
        let wallet = global.wallet.as_mut().ok_or(Error::Forbidden)?;
        wallet
            .trust_feed(now)
            .await
            .map_err(Error::Unavailable.redact())?;
        let completed = self.inner.clock.now();
        if completed < now {
            return Err(Error::Unavailable);
        }
        let feed = wallet
            .published_feed(completed)
            .map_err(Error::Unavailable.redact())?;
        Ok(TrustFeed {
            revision: feed.revision,
            policy_epoch: feed.policy_epoch,
            key_ring: feed.key_ring.clone(),
            key_transitions: feed
                .key_transitions
                .iter()
                .map(|entry| TrustKeyTransition {
                    revision: entry.revision,
                    proof: entry.proof.clone(),
                })
                .collect(),
            manifest: feed.manifest.clone(),
            settings: feed.settings.clone(),
            schema: feed.schema.clone(),
            schema_versions: feed.schema_versions.clone(),
            communities: feed.communities.clone(),
            revocations: feed.revocations.clone(),
            root_board: feed.root_board.clone(),
            balance: feed.balance.clone(),
        })
    }
    pub(crate) async fn wallet_trust_changes(
        &self,
        ctx: Context,
        request: Since,
    ) -> Result<Announcement> {
        let mut global = self.global_backend()?.lock().await;
        let now = self.inner.clock.now();
        if now < ctx.now {
            return Err(Error::Unavailable);
        }
        let wallet = global.wallet.as_mut().ok_or(Error::Forbidden)?;
        let notice = wallet
            .trust_changes(request.revision, now)
            .await
            .map_err(Error::Unavailable.redact())?;
        let completed = self.inner.clock.now();
        if completed < now {
            return Err(Error::Unavailable);
        }
        wallet
            .published_feed(completed)
            .map_err(Error::Unavailable.redact())?;
        Ok(Announcement {
            revision: notice.revision,
            policy_epoch: notice.policy_epoch,
            changed: notice.changed,
        })
    }
}

impl Door {
    pub(crate) async fn wallet_add_passkey(
        &self,
        ctx: Context,
        request: AddPasskey,
    ) -> Result<AddedPasskey> {
        let token = ctx.token.as_deref().ok_or(Error::Unauthorized)?;
        let authentication = self.auth(&ctx.host)?;
        let mut auth = authentication.lock().await;
        let mut session = auth
            .wallet_session(
                token,
                ctx.grant.as_ref().ok_or(Error::Unauthorized)?,
                ctx.now,
                self.inner.clock.as_ref(),
            )
            .await?;
        let mut global = self.global_backend()?.lock().await;
        session
            .check(&mut auth, token, ctx.now, self.inner.clock.as_ref())
            .await?;
        let writing = matches!(request, AddPasskey::Finish { .. });
        auth.check_passkey_addition(token, &request, session.checked_at()?)?;
        let mutation = if writing {
            global.wallet_mutation().await?
        } else {
            None
        };
        if let Some(mutation) = &mutation {
            global
                .signal_wallet_mutation(&session, mutation, self.inner.clock.as_ref())
                .await?;
        }
        let result = auth
            .add_passkey_wallet(token, request, session.checked_at()?, mutation)
            .await;
        let finish = async {
            let added = result?;
            let completed = session
                .check(
                    &mut auth,
                    token,
                    session.checked_at()?,
                    self.inner.clock.as_ref(),
                )
                .await?;
            if writing {
                global.publish_wallet(completed).await?;
            }
            let completed = session
                .check(&mut auth, token, completed, self.inner.clock.as_ref())
                .await?;
            session.check_sync(&auth, token, completed, self.inner.clock.as_ref())?;
            Ok(added)
        }
        .await;
        finish.map_err(|error| if writing { Error::Reconcile } else { error })
    }
    pub(crate) async fn wallet_revoke_passkey(
        &self,
        ctx: Context,
        request: RevokePasskey,
    ) -> Result<Empty> {
        let token = ctx.token.as_deref().ok_or(Error::Unauthorized)?;
        let authentication = self.auth(&ctx.host)?;
        let mut auth = authentication.lock().await;
        let mut session = auth
            .wallet_session(
                token,
                ctx.grant.as_ref().ok_or(Error::Unauthorized)?,
                ctx.now,
                self.inner.clock.as_ref(),
            )
            .await?;
        let mut global = self.global_backend()?.lock().await;
        session
            .check(&mut auth, token, ctx.now, self.inner.clock.as_ref())
            .await?;
        let mutation = global.wallet_mutation().await?;
        if let Some(mutation) = &mutation {
            global
                .signal_wallet_mutation(&session, mutation, self.inner.clock.as_ref())
                .await?;
        }
        let result = auth
            .revoke_passkey_wallet(
                token,
                request.credential.into(),
                session.checked_at()?,
                mutation,
            )
            .await;
        let finish = async {
            result?;
            // Even current-key revocation publishes its actual tombstone before
            // reporting uncertainty; no ended session grants further authority.
            let now = self.inner.clock.now();
            if now < session.checked_at()? {
                return Err(Error::Unauthorized);
            }
            global.publish_wallet(now).await?;
            let completed = session
                .check(&mut auth, token, now, self.inner.clock.as_ref())
                .await?;
            session.check_sync(&auth, token, completed, self.inner.clock.as_ref())?;
            Ok(Empty {})
        }
        .await;
        finish.map_err(|_| Error::Reconcile)
    }
}

impl Door {
    pub(crate) async fn wallet_register_finish(
        &self,
        ctx: Context,
        request: RegisterFinish,
    ) -> Result<User> {
        let authentication = self.auth(&ctx.host)?;
        let mut auth = authentication.lock().await;
        if auth.role != Role::Member || auth.operator.is_some() {
            return auth
                .register_finish_live(request, ctx.now, self.inner.clock.as_ref())
                .await;
        }
        let mut global = self.global_backend()?.lock().await;
        let mutation = global.wallet_mutation().await?;
        auth.register_finish_wallet_live(request, ctx.now, self.inner.clock.as_ref(), mutation)
            .await
    }
    pub(crate) async fn wallet_login_finish(
        &self,
        ctx: Context,
        request: LoginFinish,
    ) -> Result<Session> {
        let authentication = self.auth(&ctx.host)?;
        let mut auth = authentication.lock().await;
        if auth.role != Role::Member || auth.operator.is_some() {
            return auth.login_finish(request, ctx.now).await;
        }
        let mut global = self.global_backend()?.lock().await;
        let mutation = global.wallet_mutation().await?;
        let session = auth.login_finish_wallet(request, ctx.now, mutation).await?;
        let completed = self.inner.clock.now();
        if completed < ctx.now || completed >= session.expires {
            auth.logout(&session.token);
            return Err(Error::Unauthorized);
        }
        Ok(session)
    }
}

#[cfg(all(test, feature = "development-gate"))]
mod tests;
