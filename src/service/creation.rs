//! Explicit caller links existing owners; no deployment or database control plane.
use super::*;

impl Door {
    /// Link an already constructed target before serving creation requests.
    /// Every target remains its own authenticated community/database owner.
    /// The launcher must explicitly supply this composition; it is not inferred.
    pub async fn link_community_creation(&self, target: &Door) -> Result<()> {
        if self.inner.scope != Scope::Global || target.inner.scope != Scope::Community {
            return Err(Error::WrongHost);
        }
        self.inner
            .root_creation_scope
            .as_ref()
            .ok_or(Error::Unavailable)?;
        let mut targets = self.inner.creation_targets.lock().await;
        let mut community = target.community_backend()?.lock().await;
        let name = community.config.community.clone();
        if targets
            .get(&name)
            .is_some_and(|old| !Arc::ptr_eq(&old.inner, &target.inner))
        {
            return Err(Error::Forbidden);
        }
        community.link_creation_owner(self.inner.creation_owner.clone())?;
        targets.insert(name, target.clone());
        Ok(())
    }
    pub(crate) async fn community_creation_recipient(
        &self,
        ctx: Context,
        request: CreationRecipientRequest,
    ) -> Result<CreationRecipient> {
        with_live_clock(
            self.community_backend()?
                .lock()
                .await
                .creation_recipient(&ctx, request),
        )
        .await
    }
    pub(crate) async fn community_creation_initialize(
        &self,
        ctx: Context,
        request: CommunityCreationRequest,
    ) -> Result<CommunityCreationInvitation> {
        let target = self
            .inner
            .creation_targets
            .lock()
            .await
            .get(&request.community)
            .cloned()
            .ok_or(Error::Unavailable)?;
        let token = ctx.token.as_deref().ok_or(Error::Unauthorized)?;
        let authentication = self.auth(&ctx.host)?;
        let mut auth = authentication.lock().await;
        let mut session = auth
            .root_creation_session(
                token,
                ctx.grant.as_ref().ok_or(Error::Unauthorized)?,
                ctx.now,
                self.inner.clock.as_ref(),
            )
            .await?;
        // Root Auth -> SAME original Root credential writer -> target service
        // -> target Policy -> target writer. A shared physical database cannot
        // acquire its second writer; original bounded acquisition refuses safely.
        let root_writer = self
            .inner
            .root_creation_scope
            .as_ref()
            .ok_or(Error::Unavailable)?
            .tx()
            .await
            .map_err(Error::Unavailable.redact())?;
        session
            .check(&mut auth, token, self.inner.clock.as_ref())
            .await?;
        let mut community = target.community_backend()?.lock().await;
        let result = with_live_clock(community.initialize_creation(
            &request.recipient,
            &self.inner.creation_owner,
            &mut session,
            &mut auth,
            token,
            self.inner.clock.as_ref(),
        ))
        .await;
        root_writer.rollback().await.map_err(|e| {
            eprintln!("DIAG svc {e:?}");
            Error::Reconcile
        })?;
        let created = result?;
        let root_floor = session
            .check(&mut auth, token, self.inner.clock.as_ref())
            .await
            .map_err(|e| {
                eprintln!("DIAG svc {e:?}");
                Error::Reconcile
            })?;
        let created = with_live_clock(community.release_creation(created, root_floor)).await?;
        let final_root = session
            .check(&mut auth, token, self.inner.clock.as_ref())
            .await
            .map_err(|e| {
                eprintln!("DIAG svc {e:?}");
                Error::Reconcile
            })?;
        let value = community.project_creation(created, final_root)?;
        if session
            .release(&auth, token, self.inner.clock.as_ref())
            .map_err(|e| {
                eprintln!("DIAG svc {e:?}");
                Error::Reconcile
            })?
            != value.checked_at
        {
            {
                eprintln!("DIAG sret {}", line!());
                return Err(Error::Reconcile);
            }
        }
        Ok(value)
    }
}

#[cfg(all(test, feature = "development-gate"))]
mod tests;
