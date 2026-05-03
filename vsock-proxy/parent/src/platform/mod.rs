/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use futures::stream::futures_unordered::FuturesUnordered;
use tokio::task::JoinHandle;

#[cfg(platform = "nitro")]
mod nitro;

pub(crate) struct GuestLaunchResult {
    pub(crate) enclave_process: JoinHandle<Result<(), String>>,

    /// Tasks whose lifecycle is tied to the guest/enclave/VM lifetime.
    /// These are cleaned up after the parent sends ExitEnclave to the enclave.
    pub(crate) enclave_tasks: FuturesUnordered<JoinHandle<Result<(), String>>>,
}

#[cfg(platform = "nitro")]
pub(crate) use nitro::{should_forward_client_logs, launch_guest};
