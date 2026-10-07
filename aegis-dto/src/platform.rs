//! Host platform identity and the roles implemented by each native backend.

use std::fmt;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::AegisHostMode;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperatingSystem {
    Ubuntu,
    ArchLinux,
    MacOs,
}

impl fmt::Display for OperatingSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ubuntu => "Ubuntu",
            Self::ArchLinux => "Arch Linux",
            Self::MacOs => "macOS",
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostPlatform {
    pub operating_system: OperatingSystem,
    pub architecture: Architecture,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    MeshLeaf,
    InboundSsh,
    ManagedUpgrade,
    Hub,
    DirectGateway,
    InternetTunnel,
    EgressGateway,
    SshLockdown,
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MeshLeaf => "mesh membership",
            Self::InboundSsh => "inbound SSH",
            Self::ManagedUpgrade => "managed upgrades",
            Self::Hub => "hub service",
            Self::DirectGateway => "direct gateway service",
            Self::InternetTunnel => "Internet tunnel mode",
            Self::EgressGateway => "Internet gateway service",
            Self::SshLockdown => "managed SSH lockdown",
        })
    }
}

impl HostPlatform {
    pub fn validate(self) -> Result<Self> {
        ensure!(
            self.operating_system != OperatingSystem::ArchLinux
                || self.architecture == Architecture::X86_64,
            "Arch Linux support requires x86_64; Arch Linux ARM is a separate distribution"
        );
        Ok(self)
    }

    pub const fn supports(self, capability: Capability) -> bool {
        match capability {
            Capability::MeshLeaf | Capability::InboundSsh | Capability::ManagedUpgrade => true,
            Capability::Hub
            | Capability::DirectGateway
            | Capability::InternetTunnel
            | Capability::EgressGateway
            | Capability::SshLockdown => !matches!(self.operating_system, OperatingSystem::MacOs),
        }
    }

    pub fn require(self, capability: Capability) -> Result<()> {
        self.validate()?;
        if !self.supports(capability) {
            return Err(UnsupportedCapability {
                platform: self,
                capability,
            }
            .into());
        }
        Ok(())
    }

    pub fn require_role(self, mode: AegisHostMode) -> Result<()> {
        self.require(match mode {
            AegisHostMode::Leaf => Capability::MeshLeaf,
            AegisHostMode::Hub => Capability::Hub,
        })
    }
}

#[derive(Debug)]
pub struct UnsupportedCapability {
    pub platform: HostPlatform,
    pub capability: Capability,
}

impl fmt::Display for UnsupportedCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} is not supported on {}",
            self.capability, self.platform.operating_system
        )
    }
}

impl std::error::Error for UnsupportedCapability {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_leaf_does_not_imply_optional_network_roles() {
        let platform = HostPlatform {
            operating_system: OperatingSystem::MacOs,
            architecture: Architecture::X86_64,
        };
        platform.require_role(AegisHostMode::Leaf).unwrap();
        platform.require(Capability::InboundSsh).unwrap();
        for capability in [
            Capability::InternetTunnel,
            Capability::EgressGateway,
            Capability::DirectGateway,
            Capability::SshLockdown,
            Capability::Hub,
        ] {
            assert!(
                platform
                    .require(capability)
                    .unwrap_err()
                    .is::<UnsupportedCapability>()
            );
        }
    }

    #[test]
    fn platform_identity_is_explicit() {
        assert!(serde_json::from_str::<HostPlatform>("{}").is_err());
        assert!(
            serde_json::from_str::<HostPlatform>(
                r#"{"operating_system":"linux","architecture":"x86_64"}"#
            )
            .is_err()
        );
        assert!(
            HostPlatform {
                operating_system: OperatingSystem::ArchLinux,
                architecture: Architecture::Aarch64
            }
            .validate()
            .is_err()
        );
    }
}
