use async_trait::async_trait;
use k256::schnorr::{
    signature::{SignatureEncoding, Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashSet, net::SocketAddr, pin::Pin, sync::Arc};
use tokio::{
    sync::{broadcast, mpsc, Mutex},
    task::JoinHandle,
};
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use tonic::{
    transport::{Channel as TonicChannel, Server},
    Request, Response, Status,
};

use crate::channel::proto::Ack;

pub mod proto {
    tonic::include_proto!("auction");
}

/// Envelope that wraps a labeled payload serialized with Serde.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageEnvelope {
    label: String,
    payload: Value,
}

impl MessageEnvelope {
    /// Creates a new envelope from a serializable payload.
    pub fn new<L, T>(label: L, payload: T) -> Result<Self, serde_json::Error>
    where
        L: Into<String>,
        T: Serialize,
    {
        Ok(Self {
            label: label.into(),
            payload: serde_json::to_value(payload)?,
        })
    }

    /// Returns the label associated with this message.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Attempts to deserialize the payload as `T`.
    pub fn decode<T>(&self) -> Result<T, serde_json::Error>
    where
        T: DeserializeOwned,
    {
        serde_json::from_value(self.payload.clone())
    }

    /// Consumes the envelope, returning the payload as `T`.
    pub fn into_payload<T>(self) -> Result<T, serde_json::Error>
    where
        T: DeserializeOwned,
    {
        serde_json::from_value(self.payload)
    }
}

// /// Sender used to publish envelopes to the broadcast channel.
// pub type EnvelopeSender = broadcast::Sender<MessageEnvelope>;

// /// Receiver used to subscribe to envelopes from the broadcast channel.
// pub type EnvelopeReceiver = broadcast::Receiver<MessageEnvelope>;

/// Error returned when sending an envelope fails.
#[derive(Debug)]
pub enum SendEnvelopeError {
    Serialize(serde_json::Error),
    Disconnected,
}

impl std::fmt::Display for SendEnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendEnvelopeError::Serialize(err) => write!(f, "failed to serialize payload: {err}"),
            SendEnvelopeError::Disconnected => write!(f, "no active receivers on channel"),
        }
    }
}

impl std::error::Error for SendEnvelopeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SendEnvelopeError::Serialize(err) => Some(err),
            SendEnvelopeError::Disconnected => None,
        }
    }
}

// /// Convenience constructor for creating a broadcast channel that carries message envelopes.
// pub fn broadcast_channel(capacity: usize) -> (EnvelopeSender, EnvelopeReceiver) {
//     broadcast::channel(capacity)
// }

// pub fn direct_channel(capacity: usize) ->   {

// }

#[async_trait]
pub trait AuctionChannel {
    async fn send_broadcast_message(&self, msg: MessageEnvelope)
    -> Result<(), AuctionChannelErorr>;
    async fn send_direct_message(&self, msg: MessageEnvelope) -> Result<(), AuctionChannelErorr>;
    async fn receive_broadcast_message(&self) -> Result<MessageEnvelope, AuctionChannelErorr>;
}

#[derive(Debug)]
pub enum AuctionChannelErorr {
    FailedToSend(String),
    FailedToReceive(String),
    AuthenticationFailed(String),
    Encoding(String),
    KeyRejected(String),
}

impl std::fmt::Display for AuctionChannelErorr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuctionChannelErorr::FailedToSend(err) => write!(f, "failed to send message: {err}"),
            AuctionChannelErorr::FailedToReceive(err) => {
                write!(f, "failed to receive message: {err}")
            }
            AuctionChannelErorr::AuthenticationFailed(err) => {
                write!(f, "authentication failed: {err}")
            }
            AuctionChannelErorr::Encoding(err) => {
                write!(f, "encoding error: {err}")
            }
            AuctionChannelErorr::KeyRejected(err) => {
                write!(f, "key rejected: {err}")
            }
        }
    }
}

impl std::error::Error for AuctionChannelErorr {}

pub fn create_envelope<L, T>(label: L, payload: T) -> Result<MessageEnvelope, SendEnvelopeError>
where
    L: Into<String>,
    T: Serialize,
{
    let envelope = MessageEnvelope::new(label, payload).map_err(SendEnvelopeError::Serialize);
    return envelope;
}

fn encode_verifying_key(key: &VerifyingKey) -> Vec<u8> {
    key.to_bytes().to_vec()
}

/// Utility to build an allowlist set from verifying keys.
pub fn allowlist_from_keys<I>(keys: I) -> HashSet<Vec<u8>>
where
    I: IntoIterator<Item = VerifyingKey>,
{
    keys.into_iter().map(|k| encode_verifying_key(&k)).collect()
}

fn sign_envelope(signing_key: &SigningKey, bytes: &[u8]) -> Vec<u8> {
    let signature: Signature = signing_key.sign(bytes);
    signature.to_vec()
}

fn verify_envelope(
    verifying_key: &VerifyingKey,
    bytes: &[u8],
    signature: &[u8],
) -> Result<(), AuctionChannelErorr> {
    let sig = Signature::try_from(signature)
        .map_err(|err| AuctionChannelErorr::AuthenticationFailed(err.to_string()))?;
    verifying_key
        .verify(bytes, &sig)
        .map_err(|err| AuctionChannelErorr::AuthenticationFailed(err.to_string()))
}

fn encode_signed_envelope(
    envelope: &MessageEnvelope,
    signing_key: &SigningKey,
    broadcast: bool,
    sender_id: impl Into<String>,
) -> Result<proto::SignedEnvelope, AuctionChannelErorr> {
    let encoded = serde_json::to_vec(envelope)
        .map_err(|err| AuctionChannelErorr::Encoding(err.to_string()))?;
    let signature = sign_envelope(signing_key, &encoded);
    let sender_public_key = encode_verifying_key(&signing_key.verifying_key());
    Ok(proto::SignedEnvelope {
        envelope: encoded,
        signature,
        broadcast,
        sender_public_key,
        sender_id: sender_id.into(),
    })
}

fn decode_signed_envelope(
    signed: &proto::SignedEnvelope,
    allowlist: &HashSet<Vec<u8>>,
) -> Result<MessageEnvelope, AuctionChannelErorr> {
    let verifying_key = VerifyingKey::from_bytes(&signed.sender_public_key).map_err(|err| {
        AuctionChannelErorr::AuthenticationFailed(format!("invalid sender key: {err}"))
    })?;

    if !allowlist.is_empty() && !allowlist.contains(&signed.sender_public_key) {
        return Err(AuctionChannelErorr::KeyRejected(
            "sender key not in allowlist".into(),
        ));
    }

    verify_envelope(&verifying_key, &signed.envelope, &signed.signature)?;

    serde_json::from_slice::<MessageEnvelope>(&signed.envelope)
        .map_err(|err| AuctionChannelErorr::Encoding(err.to_string()))
}

#[derive(Clone)]
struct AuctionGrpcService {
    allowed_signers: HashSet<Vec<u8>>,
    direct_tx: mpsc::UnboundedSender<MessageEnvelope>,
    broadcast_tx: broadcast::Sender<proto::SignedEnvelope>,
}

#[tonic::async_trait]
impl proto::auction_channel_server::AuctionChannel for AuctionGrpcService {
    async fn publish(
        &self,
        request: Request<proto::SignedEnvelope>,
    ) -> Result<Response<proto::Ack>, Status> {
        let signed = request.into_inner();
        let envelope =
            decode_signed_envelope(&signed, &self.allowed_signers).map_err(|err| match err {
                AuctionChannelErorr::AuthenticationFailed(msg)
                | AuctionChannelErorr::Encoding(msg)
                | AuctionChannelErorr::KeyRejected(msg) => Status::unauthenticated(msg),
                other => Status::internal(other.to_string()),
            })?;

        if signed.broadcast {
            self.broadcast_tx
                .send(signed)
                .map_err(|err| Status::internal(err.to_string()))?;
        } else {
            self.direct_tx
                .send(envelope)
                .map_err(|err| Status::internal(err.to_string()))?;
        }

        Ok(Response::new(proto::Ack {
            ok: true,
            error: String::new(),
        }))
    }

    type SubscribeStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<proto::SignedEnvelope, Status>> + Send + 'static>>;

    async fn subscribe(
        &self,
        _request: Request<proto::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let rx = self.broadcast_tx.subscribe();
        let stream = BroadcastStream::new(rx).map(|result| match result {
            Ok(env) => Ok(env),
            Err(err) => Err(Status::unavailable(format!(
                "broadcast stream failed: {err}"
            ))),
        });

        Ok(Response::new(Box::pin(stream)))
    }
}

/// Seller-facing gRPC channel. The seller runs the gRPC server and
/// receives bidders' direct messages while broadcasting authenticated
/// envelopes to all connected bidders.
pub struct GrpcSellerChannel {
    signing_key: SigningKey,
    direct_rx: Mutex<mpsc::UnboundedReceiver<MessageEnvelope>>,
    broadcast_tx: broadcast::Sender<proto::SignedEnvelope>,
    _server_handle: JoinHandle<()>,
}

impl GrpcSellerChannel {
    pub async fn serve(
        addr: SocketAddr,
        signing_key: SigningKey,
        allowed_signers: impl Into<HashSet<Vec<u8>>>,
    ) -> Result<Self, AuctionChannelErorr> {
        let allowed = allowed_signers.into();

        let (direct_tx, direct_rx) = mpsc::unbounded_channel();
        let (broadcast_tx, _) = broadcast::channel(256);

        let service = AuctionGrpcService {
            allowed_signers: allowed.clone(),
            direct_tx,
            broadcast_tx: broadcast_tx.clone(),
        };

        let server = Server::builder()
            .add_service(proto::auction_channel_server::AuctionChannelServer::new(
                service,
            ))
            .serve(addr);

        let handle = tokio::spawn(async move {
            if let Err(err) = server.await {
                eprintln!("grpc server stopped: {err}");
            }
        });

        Ok(Self {
            signing_key,
            direct_rx: Mutex::new(direct_rx),
            broadcast_tx,
            _server_handle: handle,
        })
    }
}

#[async_trait]
impl AuctionChannel for GrpcSellerChannel {
    async fn send_broadcast_message(
        &self,
        msg: MessageEnvelope,
    ) -> Result<(), AuctionChannelErorr> {
        let signed = encode_signed_envelope(&msg, &self.signing_key, true, "seller")?;
        self.broadcast_tx
            .send(signed)
            .map(|_| ())
            .map_err(|err| AuctionChannelErorr::FailedToSend(err.to_string()))
    }

    async fn send_direct_message(&self, _msg: MessageEnvelope) -> Result<(), AuctionChannelErorr> {
        Err(AuctionChannelErorr::FailedToSend(
            "seller channel does not support outbound direct messages".into(),
        ))
    }

    async fn receive_broadcast_message(&self) -> Result<MessageEnvelope, AuctionChannelErorr> {
        Err(AuctionChannelErorr::FailedToReceive(
            "seller channel does not listen for broadcast messages".into(),
        ))
    }
}

/// Bidder-facing gRPC channel. Each bidder connects to the seller's
/// server, subscribes to broadcasts, and publishes messages back to the seller.
pub struct GrpcBidderChannel {
    signing_key: SigningKey,
    bidder_id: String,
    client: Arc<Mutex<proto::auction_channel_client::AuctionChannelClient<TonicChannel>>>,
    broadcast_rx: Arc<Mutex<mpsc::UnboundedReceiver<MessageEnvelope>>>,
}

impl Clone for GrpcBidderChannel {
    fn clone(&self) -> Self {
        Self {
            signing_key: self.signing_key.clone(),
            bidder_id: self.bidder_id.clone(),
            client: Arc::clone(&self.client),
            broadcast_rx: Arc::clone(&self.broadcast_rx),
        }
    }
}

impl GrpcBidderChannel {
    pub async fn connect(
        endpoint: String,
        bidder_id: impl Into<String>,
        signing_key: SigningKey,
        allowed_signers: impl Into<HashSet<Vec<u8>>>,
    ) -> Result<Self, AuctionChannelErorr> {
        let bidder_id = bidder_id.into();
        let allowed = allowed_signers.into();

        let client = proto::auction_channel_client::AuctionChannelClient::connect(
            endpoint.clone(),
        )
        .await
        .map_err(|err| AuctionChannelErorr::FailedToSend(err.to_string()))?;

        let mut subscribe_client = client.clone();
        let (broadcast_tx, broadcast_rx) = mpsc::unbounded_channel();
        let bidder_for_task = bidder_id.clone();
        let allowed_for_task = allowed.clone();

        tokio::spawn(async move {
            match subscribe_client
                .subscribe(proto::SubscribeRequest {
                    bidder_id: bidder_for_task,
                })
                .await
            {
                Ok(response) => {
                    let mut stream = response.into_inner();
                    while let Ok(message) = stream.message().await {
                        match message {
                            Some(signed) => match decode_signed_envelope(&signed, &allowed_for_task) {
                                Ok(envelope) => {
                                    let _ = broadcast_tx.send(envelope);
                                }
                                Err(err) => {
                                    eprintln!("failed to verify broadcast message: {err}");
                                }
                            },
                            None => break,
                        }
                    }
                }
                Err(err) => {
                    eprintln!("failed to subscribe to seller broadcasts: {err}");
                }
            }
        });

        Ok(Self {
            signing_key,
            bidder_id,
            client: Arc::new(Mutex::new(client)),
            broadcast_rx: Arc::new(Mutex::new(broadcast_rx)),
        })
    }
}

#[async_trait]
impl AuctionChannel for GrpcBidderChannel {
    async fn send_broadcast_message(
        &self,
        msg: MessageEnvelope,
    ) -> Result<(), AuctionChannelErorr> {
        let signed = encode_signed_envelope(
            &msg,
            &self.signing_key,
            true,
            self.bidder_id.clone(),
        )?;

        let mut client = self.client.lock().await;
        let response = client
            .publish(signed)
            .await
            .map_err(|err| AuctionChannelErorr::FailedToSend(err.to_string()))?
            .into_inner();

        if response.ok {
            Ok(())
        } else {
            Err(AuctionChannelErorr::FailedToSend(response.error))
        }
    }

    async fn send_direct_message(&self, msg: MessageEnvelope) -> Result<(), AuctionChannelErorr> {
        let signed = encode_signed_envelope(
            &msg,
            &self.signing_key,
            false,
            self.bidder_id.clone(),
        )?;

        let mut client = self.client.lock().await;
        let response = client
            .publish(signed)
            .await
            .map_err(|err| AuctionChannelErorr::FailedToSend(err.to_string()))?
            .into_inner();

        if response.ok {
            Ok(())
        } else {
            Err(AuctionChannelErorr::FailedToSend(response.error))
        }
    }


    async fn receive_broadcast_message(&self) -> Result<MessageEnvelope, AuctionChannelErorr> {
        let mut rx = self.broadcast_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| AuctionChannelErorr::FailedToReceive("broadcast stream ended".into()))
    }
}

// /// Receives the next envelope from the provided receiver.
// pub async fn receive_envelope(
//     receiver: &mut EnvelopeReceiver,
// ) -> Result<MessageEnvelope, broadcast::error::RecvError> {
//     receiver.recv().await
// }

// Converts a broadcast receiver into an asynchronous stream of envelopes.
// pub fn stream_envelopes(receiver: EnvelopeReceiver) -> BroadcastStream<MessageEnvelope> {
//     BroadcastStream::new(receiver)
// }

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::{Mutex, broadcast, mpsc};

    struct InMemoryAuctionChannelInner {
        broadcast_tx: broadcast::Sender<MessageEnvelope>,
        direct_tx: mpsc::UnboundedSender<MessageEnvelope>,
        direct_rx: Mutex<mpsc::UnboundedReceiver<MessageEnvelope>>,
    }

    pub struct InMemoryAuctionChannel {
        inner: Arc<InMemoryAuctionChannelInner>,
        broadcast_rx: Mutex<broadcast::Receiver<MessageEnvelope>>,
    }

    impl InMemoryAuctionChannel {
        pub fn new() -> Self {
            let (broadcast_tx, broadcast_rx) = broadcast::channel(64);
            let (direct_tx, direct_rx) = mpsc::unbounded_channel();

            Self {
                inner: Arc::new(InMemoryAuctionChannelInner {
                    broadcast_tx,
                    direct_tx,
                    direct_rx: Mutex::new(direct_rx),
                }),
                broadcast_rx: Mutex::new(broadcast_rx),
            }
        }
    }

    impl Clone for InMemoryAuctionChannel {
        fn clone(&self) -> Self {
            Self {
                inner: Arc::clone(&self.inner),
                broadcast_rx: Mutex::new(self.inner.broadcast_tx.subscribe()),
            }
        }
    }

    #[async_trait]
    impl AuctionChannel for InMemoryAuctionChannel {
        async fn send_broadcast_message(
            &self,
            msg: MessageEnvelope,
        ) -> Result<(), AuctionChannelErorr> {
            self.inner
                .broadcast_tx
                .send(msg)
                .map(|_| ())
                .map_err(|err| AuctionChannelErorr::FailedToSend(err.to_string()))
        }

        async fn send_direct_message(
            &self,
            msg: MessageEnvelope,
        ) -> Result<(), AuctionChannelErorr> {
            self.inner
                .direct_tx
                .send(msg)
                .map_err(|err| AuctionChannelErorr::FailedToSend(err.to_string()))
        }


        async fn receive_broadcast_message(&self) -> Result<MessageEnvelope, AuctionChannelErorr> {
            let mut rx = self.broadcast_rx.lock().await;
            rx.recv()
                .await
                .map_err(|err| AuctionChannelErorr::FailedToReceive(err.to_string()))
        }
    }
}
