//! Shared client workflows for Aegis frontends.
//!
//! Initialize [`crate::ui`] once before running an interactive workflow.

pub use crate::api::AuthenticatedApiClient;
pub use crate::config::{UserContext, app_dir, now_unix};
pub use crate::locks::{deployment_lock, local_system_lock};

pub mod login {
    pub use crate::app::login::{BrowserProof, browser_proof, import_credential_file};
}

pub mod enrollment {
    pub use crate::app::enroll_install::{
        system_agent_activation_script, system_program_bootstrap_script,
    };
    pub use crate::app::{
        check_local_enrollment_platform, enroll_local_machine, local_machine_alias,
        local_machine_ready,
    };
    pub use crate::invitation::{issue, path, read, reserve};
}
