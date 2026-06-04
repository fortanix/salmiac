/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use futures::stream::futures_unordered::FuturesUnordered;
use tokio::task::JoinHandle;

#[cfg(platform = "nitro")]
mod nitro;
#[cfg(platform = "simulator")]
mod simulator;
#[cfg(platform = "snp")]
mod snp;

pub(crate) type GuestTasks = FuturesUnordered<JoinHandle<Result<(), String>>>;

#[cfg(platform = "simulator")]
pub(crate) use simulator::{
    launch_guest, should_forward_client_logs, start_post_connect_guest_tasks,
};

#[cfg(platform = "snp")]
pub(crate) use snp::{launch_guest, should_forward_client_logs, start_post_connect_guest_tasks};

#[cfg(platform = "nitro")]
pub(crate) use nitro::{launch_guest, should_forward_client_logs, start_post_connect_guest_tasks};

pub(crate) struct GuestLaunchResult {
    pub(crate) enclave_process: JoinHandle<Result<(), String>>,
}
