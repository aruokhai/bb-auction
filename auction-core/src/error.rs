pub enum AuctionError {
    DkgNotCompleted,
    BidNotSet,
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