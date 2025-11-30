use auction_core::{
    bidder::Bidder,
    brandt::AuctionParams,
    channel::GrpcBidderChannel,
    rate::RateParams,
    seller::Seller,
};
use k256::{elliptic_curve::Field, Scalar};
use rand::{rngs::StdRng, SeedableRng};
use std::{
    collections::HashSet,
    net::{SocketAddr, TcpListener},
    time::Duration,
};
use tokio::time::{sleep, timeout};

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn grpc_bidders_and_seller_flow_completes() {
    let auction_params = AuctionParams {
        rate: RateParams {
            min_bps: 100,
            max_bps: 1000,
            step_bps: 100,
        },
        m: 1,
        num_bidders: 10,
    };

    let addr: SocketAddr = TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("read local address");
    let _seller = Seller::new(StdRng::seed_from_u64(42), addr, auction_params.clone()).await;

    // Give the gRPC server a brief moment to start listening before bidders connect.
    sleep(Duration::from_millis(50)).await;

    // Warmup connection to ensure the server is accepting connections before spinning up bidders.
    let mut warmup_rng = StdRng::seed_from_u64(777);
    let warmup_secret = Scalar::random(&mut warmup_rng);
    let warmup_signing =
        k256::schnorr::SigningKey::from_bytes(&warmup_secret.to_bytes()).expect("valid warmup key");
    let _warmup = GrpcBidderChannel::connect(
        format!("http://{}", addr),
        "warmup",
        warmup_signing,
        HashSet::new(),
    )
    .await
    .expect("warmup bidder connects");

    let mut bidders = Vec::with_capacity(auction_params.num_bidders as usize);
    let mut bidder_bids = Vec::with_capacity(auction_params.num_bidders as usize);

    for idx in 0..auction_params.num_bidders {
        let rng = StdRng::seed_from_u64(10_000 + idx);
        let mut bidder =
            Bidder::new(rng, format!("http://{}", addr)).await;
        let bid_rate = auction_params.rate.max_bps - idx * auction_params.rate.step_bps;
        let bidder_pk = bidder.public_key();
        bidder_bids.push((bidder_pk, bid_rate));

        bidder
            .announce_public_key()
            .await
            .expect("bidder key announcement succeeds");
        bidder.initiate_bid(auction_params.clone(), bid_rate).await;
        bidders.push(bidder);
    }

    let outcomes: Vec<(u64, bool)> =
        timeout(Duration::from_secs(300), async {
            let mut results = Vec::with_capacity(bidders.len());

            for (bidder, (_, rate)) in bidders.iter().zip(bidder_bids.iter()) {
                let is_winner = bidder.wait_for_final_outcome().await;
                results.push((*rate, is_winner));
            }

            results
        })
        .await
        .expect("bidders should finish auction flow");

    let winner_count = outcomes.iter().filter(|(_, is_winner)| *is_winner).count();
    assert_eq!(
        winner_count, 1,
        "exactly one bidder should be flagged as winner"
    );

    let winning_rate = outcomes
        .iter()
        .find_map(|(rate, is_winner)| if *is_winner { Some(*rate) } else { None })
        .expect("a winner rate should be present");
    let lowest_rate = outcomes
        .iter()
        .map(|(rate, _)| *rate)
        .min()
        .expect("at least one rate should exist");

    assert_eq!(
        winning_rate, lowest_rate,
        "lowest rate bidder should win the auction"
    );
}
