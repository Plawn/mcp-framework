//! Dynamic capability system for runtime tool/prompt/resource management.
//!
//! Use [`CapabilityRegistry`] to add or remove tools, prompts, and resources at runtime.
//! Use [`CapabilityFilter`] to control which capabilities are visible per session
//! (e.g., based on the authenticated user's token or role).

mod filter;
mod handler;
mod registry;

pub use filter::{CapabilityFilter, PromptFilter, ResourceFilter, ToolFilter};
pub use registry::CapabilityRegistry;
pub(crate) use handler::DynamicHandler;
