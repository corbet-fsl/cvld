//! Original community role management, without public profile badges.
use super::*;

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberRole {
    pub member: String,
    pub role: Role,
}

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetMemberRole {
    /// Target's community pseudonym from the original enrolment lobby.
    pub member: String,
    pub role: Role,
}
