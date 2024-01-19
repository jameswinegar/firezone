//! Inter-process communication for the connlib subprocess
//!
//! Everything in here that constructs or uses a `Client` or `Server`,
//! requires a Tokio reactor context.

use anyhow::{Context, Result};
use connlib_client_shared::ResourceDescription;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    ffi::c_void,
    marker::Unpin,
    os::windows::io::{AsHandle, AsRawHandle},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::windows::named_pipe,
};
use windows::Win32::{
    Foundation::HANDLE,
    System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectA, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    },
};

/// Uses a Windows job object to kill child processes when the parent exits
pub(crate) struct LeakGuard {
    job_object: HANDLE,
}

impl LeakGuard {
    pub fn new() -> Result<Self> {
        let job_object = unsafe { CreateJobObjectA(None, None) }?;

        let mut jeli = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: Windows shouldn't hang on to `jeli`. I'm not sure why this is unsafe.
        unsafe {
            SetInformationJobObject(
                job_object,
                JobObjectExtendedLimitInformation,
                &jeli as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION as *const c_void,
                u32::try_from(std::mem::size_of_val(&jeli))?,
            )
        }?;

        Ok(Self { job_object })
    }

    pub fn add_process(&self, process: &std::process::Child) -> Result<()> {
        // Process IDs are not the same as handles, so get a handle to the process.
        let process_handle = process.as_handle();
        // SAFETY: The docs say this is UB since the null pointer doesn't belong to the same allocated object as the handle.
        // I couldn't get `OpenProcess` to work, and I don't have any other way to convert the process ID to a handle safely.
        // Since the handles aren't pointers per se, maybe it'll work?
        let process_handle =
            HANDLE(unsafe { process_handle.as_raw_handle().offset_from(std::ptr::null()) });
        // SAFETY: TODO
        unsafe { AssignProcessToJobObject(self.job_object, process_handle) }
            .context("AssignProcessToJobObject")?;
        Ok(())
    }
}

/// Returns a random valid named pipe ID based on a UUIDv4
///
/// e.g. "\\.\pipe\dev.firezone.client\9508e87c-1c92-4630-bb20-839325d169bd"
pub(crate) fn random_pipe_id() -> String {
    format!(r"\\.\pipe\dev.firezone.client\{}", uuid::Uuid::new_v4())
}

/// A server that accepts only one client
pub(crate) struct UnconnectedServer {
    pipe: named_pipe::NamedPipeServer,
}

impl UnconnectedServer {
    // Will be used for production code soon
    pub fn new() -> anyhow::Result<(Self, String)> {
        let id = random_pipe_id();
        let this = Self::new_with_id(&id)?;
        Ok((this, id))
    }

    pub fn new_with_id(id: &str) -> anyhow::Result<Self> {
        let pipe = named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(id)?;

        Ok(Self { pipe })
    }

    pub async fn connect(self) -> anyhow::Result<Server> {
        self.pipe.connect().await?;
        Ok(Server { pipe: self.pipe })
    }
}

/// A server that's connected to a client
pub(crate) struct Server {
    pipe: named_pipe::NamedPipeServer,
}

/// A client that's connected to a server
pub(crate) struct Client {
    pipe: named_pipe::NamedPipeClient,
}

#[derive(Deserialize, Serialize)]
pub(crate) enum Request {
    AwaitCallback,
    Connect,
    Disconnect,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub(crate) enum Response {
    CallbackOnUpdateResources(Vec<ResourceDescription>),
    CallbackTunnelReady,
    Connected,
    Disconnected,
}

#[must_use]
pub(crate) struct Responder<'a> {
    client: &'a mut Client,
}

impl Server {
    pub async fn request(&mut self, req: Request) -> Result<Response> {
        write_bincode(&mut self.pipe, &req)
            .await
            .context("couldn't send request")?;
        read_bincode(&mut self.pipe)
            .await
            .context("couldn't read response")
    }
}

impl Client {
    pub fn new(server_id: &str) -> Result<Self> {
        let pipe = named_pipe::ClientOptions::new().open(server_id)?;
        Ok(Self { pipe })
    }

    pub async fn next_request(&mut self) -> Result<(Request, Responder)> {
        let req = read_bincode(&mut self.pipe).await?;
        let responder = Responder { client: self };
        Ok((req, responder))
    }
}

impl<'a> Responder<'a> {
    pub async fn respond(self, resp: Response) -> Result<()> {
        write_bincode(&mut self.client.pipe, &resp).await?;
        Ok(())
    }
}

/// Reads a message from an async reader, with a 32-bit little-endian length prefix
async fn read_bincode<R: AsyncRead + Unpin, T: DeserializeOwned>(reader: &mut R) -> Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf);
    let mut buf = vec![0u8; usize::try_from(len)?];
    reader.read_exact(&mut buf).await?;
    let msg = bincode::deserialize(&buf)?;
    Ok(msg)
}

/// Writes a message to an async writer, with a 32-bit little-endian length prefix
async fn write_bincode<W: AsyncWrite + Unpin, T: Serialize>(writer: &mut W, msg: &T) -> Result<()> {
    let buf = bincode::serialize(msg)?;
    let len = u32::try_from(buf.len())?.to_le_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&buf).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    /// Test just the happy path
    /// It's hard to simulate a process crash because:
    /// - If I Drop anything, Tokio will clean it up
    /// - If I `std::mem::forget` anything, the test process is still running, so Windows will not clean it up
    ///
    /// TODO: Simulate crashes of processes involved in IPC using our own test framework
    #[test]
    fn happy_path() -> anyhow::Result<()> {
        let rt = Runtime::new()?;
        rt.block_on(async move {
            // Pretend we're in the main process
            let (server, server_id) = UnconnectedServer::new()?;

            let worker_task = tokio::spawn(async move {
                // Pretend we're in a worker process
                let mut client = Client::new(&server_id)?;

                // Handle requests from the main process
                loop {
                    let (req, responder) = client.next_request().await?;
                    let resp = match &req {
                        Request::AwaitCallback => Response::CallbackOnUpdateResources(vec![]),
                        Request::Connect => Response::Connected,
                        Request::Disconnect => Response::Disconnected,
                    };
                    responder.respond(resp).await?;

                    if let Request::Disconnect = req {
                        break;
                    }
                }
                Ok::<_, anyhow::Error>(())
            });

            let mut server = server.connect().await?;

            let start_time = std::time::Instant::now();
            assert_eq!(server.request(Request::Connect).await?, Response::Connected);
            assert_eq!(
                server.request(Request::AwaitCallback).await?,
                Response::CallbackOnUpdateResources(vec![])
            );
            assert_eq!(
                server.request(Request::Disconnect).await?,
                Response::Disconnected
            );

            let elapsed = start_time.elapsed();
            assert!(
                elapsed < std::time::Duration::from_millis(6),
                "{:?}",
                elapsed
            );

            // Make sure the worker 'process' exited
            worker_task.await??;

            Ok::<_, anyhow::Error>(())
        })?;
        Ok(())
    }
}
