use crate::channel::AuctionChannelErorr;

#[derive(Debug)]
pub enum AuctionError {
    DkgNotCompleted,
    BidNotSet,
    BidPublishErr(AuctionChannelErorr),
    BroadcastError(AuctionChannelErorr),
    InvalidBidIndex,
    BidVectorNotSet,
    SerializationError,
    DeserializationError,
    ProofVerificationFailed,
    EncryptionError,
    DecryptionError,
    Other(String),
}
