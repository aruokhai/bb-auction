use crate::channel::BidChannelErorr;

pub enum AuctionError {
    DkgNotCompleted,
    BidNotSet,
    BidPublishErr(BidChannelErorr),
    BroadcastError,
    InvalidBidIndex,
    BidVectorNotSet,
    SerializationError,
    DeserializationError,
    ProofVerificationFailed,
    EncryptionError,
    DecryptionError,
    Other(String),
}