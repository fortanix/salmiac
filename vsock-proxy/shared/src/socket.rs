/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::io;
use std::io::Error;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::task::{Context, Poll};

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::{Mutex, MutexGuard};
use tokio_vsock::VsockStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

#[derive(Clone)]
pub struct AsyncVsockStream(Arc<Mutex<VsockStream>>);

impl AsyncVsockStream {
    pub fn new(socket: VsockStream) -> Self {
        AsyncVsockStream(Arc::new(Mutex::new(socket)))
    }

    /// Exchanges messages with the other side of the VSockStream. Ensures that the returned
    /// message is a response to the message sent. Currently this is achieved through locking, in
    /// the future other means can be used.
    pub async fn exchange_message<S: Serialize + Send + Sync, R: DeserializeOwned>(&mut self, msg: &S) -> Result<R, String> {
        log::debug!("Requesting temp vsock lock");
        let mut socket = self.0.lock().await;
        socket.write_lv(msg).await?;
        socket.read_lv().await?
    }

    /// Accessing a VsockStream directly can be dangerous in a multithreaded context as messages
    /// need to be exchanged in a specific order. This takes a lock on the stream to ensure no
    /// other threads are able to access it
    /// The use of this function needs to be avoid when possible as it prevents further performance
    /// improvements such as sending the next message to the other side when a response hasn't been
    /// received yet
    pub async fn lock<'a>(&'a self) -> MutexGuard<'a, VsockStream> {
        log::debug!("Requesting vsock lock");
        self.0.lock().await
    }
}

/// Stream abstraction for length-value framing
#[async_trait]
pub trait AsyncWriteLvStream: AsyncWrite {
    async fn write_lv_bytes(&mut self, data: &[u8]) -> Result<(), String>;

    async fn write_lv<T: Serialize + Send + Sync>(&mut self, value: &T) -> Result<(), String>;
}

#[async_trait]
pub trait AsyncReadLvStream: AsyncRead {
    async fn read_lv_bytes(&mut self) -> Result<Vec<u8>, String>;

    async fn read_lv<T: DeserializeOwned>(&mut self) -> Result<T, String>;
}

#[async_trait]
impl<U> AsyncWriteLvStream for U
where
    U: AsyncWrite + Unpin + Send,
{
    async fn write_lv_bytes(&mut self, data: &[u8]) -> Result<(), String> {
        self.write_u64_le(data.len() as u64)
            .await
            .map_err(|err| format!("Failed to write u64 to vsock. {}", err.to_error_string()))?;

        self.write_all(data)
            .await
            .map_err(|err| format!("Failed to write bytes to vsock. {}", err.to_error_string()))
    }

    async fn write_lv<T: Serialize + Send + Sync>(&mut self, arg: &T) -> Result<(), String> {
        let bytes = serde_cbor::to_vec(arg).map_err(|err| format!("Failed to serialize struct {:?}", err))?;

        Self::write_lv_bytes(self, &bytes).await
    }
}

#[async_trait]
impl<U> AsyncReadLvStream for U
where
    U: AsyncRead + Unpin + Send,
{
    async fn read_lv_bytes(&mut self) -> Result<Vec<u8>, String> {
        let len = self
            .read_u64_le()
            .await
            .map_err(|err| format!("Failed to read u64 from vsock. {}", err.to_error_string()))?;

        let mut buf = vec![0 as u8; len as usize];

        self.read_exact(&mut buf).await.map_err(|err| {
            format!(
                "Failed to read array of len {} from vsock. {}",
                buf.len(),
                err.to_error_string()
            )
        })?;

        Ok(buf)
    }

    async fn read_lv<T: DeserializeOwned>(&mut self) -> Result<T, String> {
        let bytes = Self::read_lv_bytes(self).await?;

        serde_cbor::from_slice(&bytes).map_err(|err| format!("Failed to deserialize struct {:?}", err))
    }
}

trait ErrorString {
    fn to_error_string(&self) -> String;
}

impl ErrorString for io::Error {
    fn to_error_string(&self) -> String {
        match self.kind() {
            io::ErrorKind::NotConnected => {
                format!("No vsock connection between enclave and parent, are they both running?")
            }
            _ => {
                format!("{}", self)
            }
        }
    }
}

/// A type that mimics the behavior of a real async socket using a two-way channel
/// This type is intended to be used only for unit testing when a real socket is expected
pub struct InMemorySocket {
    sender: Sender<Vec<u8>>,

    receiver: Receiver<Vec<u8>>,
}

impl InMemorySocket {
    /// Create a socket pair which are connected to each other via two channels
    pub fn socket_pair() -> (InMemorySocket, InMemorySocket) {
        let (to_parent, from_enclave) = mpsc::channel();
        let (to_enclave, from_parent) = mpsc::channel();

        let enclave_socket = InMemorySocket {
            sender: to_parent,
            receiver: from_parent,
        };

        let parent_socket = InMemorySocket {
            sender: to_enclave,
            receiver: from_enclave,
        };

        (enclave_socket, parent_socket)
    }
}

impl AsyncWrite for InMemorySocket {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match self.sender.send(buf.to_vec()).map(|_| buf.len() as usize) {
            Ok(result) => Poll::Ready(Ok(result)),
            // Returning 0 means that accepting channel doesn't accept any more data
            // We do this to gracefully exit from a write function even if the accepting channel is closed
            Err(_) => Poll::Ready(Ok(0)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for InMemorySocket {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.receiver.recv() {
            Ok(result) => {
                buf.put_slice(&result);
                Poll::Ready(Ok(()))
            }
            // Not change the buffer means that accepting channel doesn't accept any more data
            // We do this to gracefully exit from a read function even if the accepting channel is closed
            Err(_) => Poll::Ready(Ok(())),
        }
    }
}
