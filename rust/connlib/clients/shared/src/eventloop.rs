use crate::{
    messages::{
        BroadcastGatewayIceCandidates, Connect, ConnectionDetails, EgressMessages,
        GatewayIceCandidates, IngressMessages, InitClient, RemoveResource, ReplyMessages,
    },
    PHOENIX_TOPIC,
};
use anyhow::{anyhow, Context as _, Result};
use async_compression::tokio::bufread::GzipEncoder;
use bimap::BiMap;
use connlib_shared::{
    messages::{
        ConnectionAccepted, DnsServer, GatewayId, GatewayResponse, IpDnsServer, ResourceAccepted,
        ResourceId,
    },
    Callbacks, IpProvider,
};
use firezone_tunnel::ClientTunnel;
use ip_network::IpNetwork;
use phoenix_channel::{ErrorReply, OutboundRequestId, PhoenixChannel};
use reqwest::header::{CONTENT_ENCODING, CONTENT_TYPE};
use std::{
    collections::HashMap,
    convert::Infallible,
    io,
    net::IpAddr,
    path::PathBuf,
    str::FromStr,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::BufReader,
    time::{Instant, Interval, MissedTickBehavior},
};
use tokio_util::codec::{BytesCodec, FramedRead};
use url::Url;

const DNS_PORT: u16 = 53;
const DNS_SENTINELS_V4: &str = "100.100.111.0/24";
const DNS_SENTINELS_V6: &str = "fd00:2021:1111:8000:100:100:111:0/120";

pub struct Eventloop<C: Callbacks> {
    tunnel: ClientTunnel<C>,
    tunnel_init: bool,

    portal: PhoenixChannel<(), IngressMessages, ReplyMessages>,
    connection_intents: SentConnectionIntents,
    log_upload_interval: tokio::time::Interval,
}

impl<C: Callbacks> Eventloop<C> {
    pub(crate) fn new(
        tunnel: ClientTunnel<C>,
        portal: PhoenixChannel<(), IngressMessages, ReplyMessages>,
    ) -> Self {
        Self {
            tunnel,
            portal,
            tunnel_init: false,
            connection_intents: SentConnectionIntents::default(),
            log_upload_interval: upload_interval(),
        }
    }
}

impl<C> Eventloop<C>
where
    C: Callbacks + 'static,
{
    #[tracing::instrument(name = "Eventloop::poll", skip_all, level = "debug")]
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Infallible>> {
        loop {
            match self.tunnel.poll_next_event(cx)? {
                Poll::Ready(event) => {
                    self.handle_tunnel_event(event);
                    continue;
                }
                Poll::Pending => {}
            }

            match self.portal.poll(cx)? {
                Poll::Ready(event) => {
                    self.handle_portal_event(event)?;
                    continue;
                }
                Poll::Pending => {}
            }

            if self.log_upload_interval.poll_tick(cx).is_ready() {
                self.portal
                    .send(PHOENIX_TOPIC, EgressMessages::CreateLogSink {});
                continue;
            }

            return Poll::Pending;
        }
    }

    fn handle_tunnel_event(&mut self, event: firezone_tunnel::Event<GatewayId>) {
        match event {
            firezone_tunnel::Event::SignalIceCandidate {
                conn_id: gateway,
                candidate,
            } => {
                tracing::debug!(%gateway, %candidate, "Sending ICE candidate to gateway");

                self.portal.send(
                    PHOENIX_TOPIC,
                    EgressMessages::BroadcastIceCandidates(BroadcastGatewayIceCandidates {
                        gateway_ids: vec![gateway],
                        candidates: vec![candidate],
                    }),
                );
            }
            firezone_tunnel::Event::ConnectionIntent {
                connected_gateway_ids,
                resource,
                ..
            } => {
                let id = self.portal.send(
                    PHOENIX_TOPIC,
                    EgressMessages::PrepareConnection {
                        resource_id: resource,
                        connected_gateway_ids,
                    },
                );
                self.connection_intents.register_new_intent(id, resource);
            }
            firezone_tunnel::Event::RefreshResources { connections } => {
                for connection in connections {
                    self.portal
                        .send(PHOENIX_TOPIC, EgressMessages::ReuseConnection(connection));
                }
            }
            firezone_tunnel::Event::SendPacket { .. } | firezone_tunnel::Event::StopPeer { .. } => {
                unreachable!("Handled internally")
            }
        }
    }

    fn handle_portal_event(
        &mut self,
        event: phoenix_channel::Event<IngressMessages, ReplyMessages>,
    ) -> Result<()> {
        match event {
            phoenix_channel::Event::InboundMessage { msg, .. } => {
                self.handle_portal_inbound_message(msg)?;
            }
            phoenix_channel::Event::SuccessResponse { res, req_id, .. } => {
                self.handle_portal_success_reply(res, req_id);
            }
            phoenix_channel::Event::ErrorResponse { res, req_id, topic } => {
                self.handle_portal_error_reply(res, topic, req_id);
            }
            phoenix_channel::Event::Disconnect(reason) => {
                return Err(anyhow!("Disconnected by portal: {reason:?}"));
            }
            phoenix_channel::Event::HeartbeatSent => {}
            phoenix_channel::Event::JoinedRoom { .. } => {}
        }

        Ok(())
    }

    fn handle_portal_inbound_message(&mut self, msg: IngressMessages) -> Result<()> {
        match msg {
            IngressMessages::ConfigChanged(_) => {
                tracing::warn!("Config changes are not yet implemented");
            }
            IngressMessages::IceCandidates(GatewayIceCandidates {
                gateway_id,
                candidates,
            }) => {
                for candidate in candidates {
                    self.tunnel.add_ice_candidate(gateway_id, candidate)
                }
            }
            IngressMessages::Init(InitClient {
                interface,
                resources,
            }) => {
                let effective_dns_servers = effective_dns_servers(
                    interface.upstream_dns.clone(),
                    self.tunnel
                        .callbacks()
                        .get_system_default_resolvers()
                        .ok()
                        .flatten()
                        .unwrap_or_default(),
                );

                let sentinel_mapping = sentinel_dns_mapping(&effective_dns_servers);

                if !self.tunnel_init {
                    self.tunnel
                        .set_interface(&interface, sentinel_mapping.clone())
                        .context("Failed to initialize interface")?;

                    self.tunnel_init = true;
                    tracing::info!("Firezone Started!");

                    for resource_description in resources {
                        let _ = self.tunnel.add_resource(resource_description);
                    }
                } else {
                    tracing::info!("Firezone reinitializated");
                }
            }
            IngressMessages::ResourceCreatedOrUpdated(resource) => {
                let resource_id = resource.id();

                if let Err(e) = self.tunnel.add_resource(resource) {
                    tracing::warn!(%resource_id, "Failed to add resource: {e}");
                }
            }
            IngressMessages::ResourceDeleted(RemoveResource(resource)) => {
                self.tunnel.remove_resource(resource);
            }
        }

        Ok(())
    }

    fn handle_portal_success_reply(&mut self, res: ReplyMessages, req_id: OutboundRequestId) {
        match res {
            ReplyMessages::Connect(Connect {
                gateway_payload:
                    GatewayResponse::ConnectionAccepted(ConnectionAccepted {
                        ice_parameters,
                        domain_response,
                    }),
                gateway_public_key,
                resource_id,
                ..
            }) => {
                if let Err(e) = self.tunnel.received_offer_response(
                    resource_id,
                    ice_parameters,
                    domain_response,
                    gateway_public_key.0.into(),
                ) {
                    tracing::warn!("Failed to accept connection: {e}");
                }
            }
            ReplyMessages::Connect(Connect {
                gateway_payload:
                    GatewayResponse::ResourceAccepted(ResourceAccepted { domain_response }),
                resource_id,
                ..
            }) => {
                if let Err(e) = self
                    .tunnel
                    .received_domain_parameters(resource_id, domain_response)
                {
                    tracing::warn!("Failed to accept resource: {e}");
                }
            }
            ReplyMessages::ConnectionDetails(ConnectionDetails {
                gateway_id,
                resource_id,
                relays,
                ..
            }) => {
                let should_accept = self
                    .connection_intents
                    .handle_connection_details_received(req_id, resource_id);

                if !should_accept {
                    tracing::debug!(%resource_id, "Ignoring stale connection details");
                    return;
                }

                match self
                    .tunnel
                    .request_connection(resource_id, gateway_id, relays)
                {
                    Ok(firezone_tunnel::Request::NewConnection(connection_request)) => {
                        // TODO: keep track for the response
                        let _id = self.portal.send(
                            PHOENIX_TOPIC,
                            EgressMessages::RequestConnection(connection_request),
                        );
                    }
                    Ok(firezone_tunnel::Request::ReuseConnection(connection_request)) => {
                        // TODO: keep track for the response
                        let _id = self.portal.send(
                            PHOENIX_TOPIC,
                            EgressMessages::ReuseConnection(connection_request),
                        );
                    }
                    Err(e) => {
                        self.tunnel.cleanup_connection(resource_id);
                        tracing::warn!("Failed to request new connection: {e}");
                    }
                };
            }
            ReplyMessages::SignedLogUrl(url) => {
                let Some(path) = self.tunnel.callbacks().roll_log_file() else {
                    return;
                };

                tokio::spawn(async move {
                    if let Err(e) = upload(path.clone(), url).await {
                        tracing::warn!(
                            "Failed to upload log file at path {path_display}: {e}. Not retrying.",
                            path_display = path.display()
                        );
                    }
                });
            }
        }
    }

    fn handle_portal_error_reply(
        &mut self,
        res: ErrorReply,
        topic: String,
        req_id: OutboundRequestId,
    ) {
        match res {
            ErrorReply::Offline => {
                let Some(offline_resource) = self.connection_intents.handle_error(req_id) else {
                    return;
                };

                tracing::debug!(resource_id = %offline_resource, "Resource is offline");

                self.tunnel.cleanup_connection(offline_resource);
            }

            ErrorReply::Disabled => {
                tracing::debug!(%req_id, "Functionality is disabled");
            }
            ErrorReply::UnmatchedTopic => {
                self.portal.join(topic, ());
            }
            ErrorReply::NotFound | ErrorReply::Other => {}
        }
    }
}

async fn upload(path: PathBuf, url: Url) -> io::Result<()> {
    tracing::info!(path = %path.display(), %url, "Uploading log file");

    let file = tokio::fs::File::open(&path).await?;

    let response = reqwest::Client::new()
        .put(url)
        .header(CONTENT_TYPE, "text/plain")
        .header(CONTENT_ENCODING, "gzip")
        .body(reqwest::Body::wrap_stream(FramedRead::new(
            GzipEncoder::new(BufReader::new(file)),
            BytesCodec::default(),
        )))
        .send()
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let status_code = response.status();

    if !status_code.is_success() {
        let body = response
            .text()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        tracing::warn!(%body, %status_code, "Failed to upload logs");

        return Err(io::Error::new(
            io::ErrorKind::Other,
            "portal returned non-successful exit code",
        ));
    }

    Ok(())
}

fn effective_dns_servers(
    upstream_dns: Vec<DnsServer>,
    default_resolvers: Vec<IpAddr>,
) -> Vec<DnsServer> {
    if !upstream_dns.is_empty() {
        return upstream_dns;
    }

    let mut dns_servers = default_resolvers
        .into_iter()
        .filter(|ip| !IpNetwork::from_str(DNS_SENTINELS_V4).unwrap().contains(*ip))
        .filter(|ip| !IpNetwork::from_str(DNS_SENTINELS_V6).unwrap().contains(*ip))
        .peekable();

    if dns_servers.peek().is_none() {
        tracing::error!("No system default DNS servers available! Can't initialize resolver. DNS will be broken.");
        return Vec::new();
    }

    dns_servers
        .map(|ip| {
            DnsServer::IpPort(IpDnsServer {
                address: (ip, DNS_PORT).into(),
            })
        })
        .collect()
}

fn sentinel_dns_mapping(dns: &[DnsServer]) -> BiMap<IpAddr, DnsServer> {
    let mut ip_provider = IpProvider::new(
        DNS_SENTINELS_V4.parse().unwrap(),
        DNS_SENTINELS_V6.parse().unwrap(),
    );

    dns.iter()
        .cloned()
        .map(|i| {
            (
                ip_provider
                    .get_proxy_ip_for(&i.ip())
                    .expect("We only support up to 256 IpV4 DNS servers and 256 IpV6 DNS servers"),
                i,
            )
        })
        .collect()
}

fn upload_interval() -> Interval {
    let duration = upload_interval_duration_from_env_or_default();
    let mut interval = tokio::time::interval_at(Instant::now() + duration, duration);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    interval
}

/// Parses an interval from the _compile-time_ env variable `CONNLIB_LOG_UPLOAD_INTERVAL_SECS`.
///
/// If not present or parsing as u64 fails, we fall back to a default interval of 5 minutes.
fn upload_interval_duration_from_env_or_default() -> Duration {
    const DEFAULT: Duration = Duration::from_secs(60 * 5);

    let Some(interval) = option_env!("CONNLIB_LOG_UPLOAD_INTERVAL_SECS") else {
        tracing::warn!(interval = ?DEFAULT, "Env variable `CONNLIB_LOG_UPLOAD_INTERVAL_SECS` was not set during compile-time, falling back to default");

        return DEFAULT;
    };

    let interval = match interval.parse() {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(interval = ?DEFAULT, "Failed to parse `CONNLIB_LOG_UPLOAD_INTERVAL_SECS` as u64: {e}");
            return DEFAULT;
        }
    };

    tracing::info!(
        ?interval,
        "Using upload interval specified at compile-time via `CONNLIB_LOG_UPLOAD_INTERVAL_SECS`"
    );

    Duration::from_secs(interval)
}

#[derive(Default)]
struct SentConnectionIntents {
    inner: HashMap<OutboundRequestId, ResourceId>,
}

impl SentConnectionIntents {
    fn register_new_intent(&mut self, id: OutboundRequestId, resource: ResourceId) {
        self.inner.insert(id, resource);
    }

    /// To be called when we receive the connection details for a particular resource.
    ///
    /// Returns whether we should accept them.
    fn handle_connection_details_received(
        &mut self,
        reference: OutboundRequestId,
        r: ResourceId,
    ) -> bool {
        let has_more_recent_intent = self
            .inner
            .iter()
            .any(|(req, resource)| req > &reference && resource == &r);

        if has_more_recent_intent {
            return false;
        }

        debug_assert!(self
            .inner
            .get(&reference)
            .is_some_and(|resource| resource == &r));
        self.inner.retain(|_, v| v != &r);

        true
    }

    fn handle_error(&mut self, req: OutboundRequestId) -> Option<ResourceId> {
        self.inner.remove(&req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discards_old_connection_intent() {
        let mut intents = SentConnectionIntents::default();

        let resource = ResourceId::random();

        intents.register_new_intent(OutboundRequestId::for_test(1), resource);
        intents.register_new_intent(OutboundRequestId::for_test(2), resource);

        let should_accept =
            intents.handle_connection_details_received(OutboundRequestId::for_test(1), resource);

        assert!(!should_accept);
    }

    #[test]
    fn allows_unrelated_intents() {
        let mut intents = SentConnectionIntents::default();

        let resource1 = ResourceId::random();
        let resource2 = ResourceId::random();

        intents.register_new_intent(OutboundRequestId::for_test(1), resource1);
        intents.register_new_intent(OutboundRequestId::for_test(2), resource2);

        let should_accept_1 =
            intents.handle_connection_details_received(OutboundRequestId::for_test(1), resource1);
        let should_accept_2 =
            intents.handle_connection_details_received(OutboundRequestId::for_test(2), resource2);

        assert!(should_accept_1);
        assert!(should_accept_2);
    }
}
