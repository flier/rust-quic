#![cfg_attr(feature = "nightly", feature(trace_macros))]
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy(conf_file = "../clippy.toml")))]

#[macro_use]
extern crate arrayref;
#[macro_use]
extern crate bitflags;
extern crate byteorder;
extern crate bytes;
extern crate extprim;
#[macro_use]
extern crate extprim_literals;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate log;
#[macro_use]
extern crate nom;
extern crate num;
#[macro_use]
extern crate num_derive;
extern crate ring;
extern crate time;

#[cfg(test)]
extern crate hex;
#[cfg(test)]
#[macro_use]
extern crate matches;
#[cfg(test)]
extern crate pretty_env_logger;

mod errors;
mod constants;
#[macro_use]
mod types;
#[macro_use]
mod packet;
pub mod crypto;
#[macro_use]
mod frames;
mod framer;

pub use framer::{QuicFramer, QuicFramerVisitor};
