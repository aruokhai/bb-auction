use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

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

/// Sender used to publish envelopes to the broadcast channel.
pub type EnvelopeSender = broadcast::Sender<MessageEnvelope>;

/// Receiver used to subscribe to envelopes from the broadcast channel.
pub type EnvelopeReceiver = broadcast::Receiver<MessageEnvelope>;

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

/// Convenience constructor for creating a broadcast channel that carries message envelopes.
pub fn channel(capacity: usize) -> (EnvelopeSender, EnvelopeReceiver) {
    broadcast::channel(capacity)
}

/// Publishes a payload with the given label on the broadcast channel.
pub fn send_envelope<L, T>(
    sender: &EnvelopeSender,
    label: L,
    payload: T,
) -> Result<(), SendEnvelopeError>
where
    L: Into<String>,
    T: Serialize,
{
    let envelope =
        MessageEnvelope::new(label, payload).map_err(SendEnvelopeError::Serialize)?;
    sender
        .send(envelope)
        .map(|_| ())
        .map_err(|_| SendEnvelopeError::Disconnected)
}

/// Receives the next envelope from the provided receiver.
pub async fn receive_envelope(
    receiver: &mut EnvelopeReceiver,
) -> Result<MessageEnvelope, broadcast::error::RecvError> {
    receiver.recv().await
}

/// Converts a broadcast receiver into an asynchronous stream of envelopes.
pub fn stream_envelopes(receiver: EnvelopeReceiver) -> BroadcastStream<MessageEnvelope> {
    BroadcastStream::new(receiver)
}
