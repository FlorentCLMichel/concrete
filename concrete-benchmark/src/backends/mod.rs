//! A module containing backends benchmarks.
//!
//! Each submodule here is expected to be activated by a given feature flag (matching the
//! `backend_*` naming), and to contain a benchmark function containing the benchmarking of every
//! entry points exposed by the backend.

#[cfg(all(feature = "backend_core", not(feature = "backend_optalysys")))]
pub mod core;

#[cfg(feature = "backend_optalysys")]
pub mod optalysys;
