//! The Windows native sandbox: a dedicated local standard account per
//! developer (`ssai-sbx-<hex>`), which owns nothing, so it reads nothing in
//! the developer's profile; a firewall rule blocks its every connection but
//! loopback, where the run's guard admits only the gateway. `ssai sandbox
//! setup` creates both, once, as an administrator.

pub mod account;
pub mod cmdline;
pub mod frame;
#[cfg(windows)]
pub mod acl;
pub mod grants;
#[cfg(windows)]
pub mod host;
#[cfg(windows)]
pub mod launch;
pub mod launch_env;
pub mod leftovers;
pub mod peer;
pub mod prepare;
#[cfg(windows)]
pub mod run;
#[cfg(windows)]
pub mod setup;
#[cfg(windows)]
pub mod sweep;
