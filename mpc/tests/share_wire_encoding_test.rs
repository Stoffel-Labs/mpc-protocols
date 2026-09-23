//! Wire encoding of secret shares: size, and "derived, not trusted".
//!
//! A `GfShare<K>` used to serialise to 17 bytes to carry one byte of secret, and a
//! `ShamirShare<F, 1, P>` to 24 to carry eight. The 16 redundant bytes in each were `id` (the
//! sender's own evaluation index, which restates the authenticated transport sender) and
//! `degree` (a session-wide constant). Both were peer-supplied, both were dealer-written metadata
//! that proves nothing, and every receiver already rejected them on mismatch rather than
//! believing them.
//!
//! `GfShareWire` / `ShamirShareWire` carry only the field elements. These tests pin
//!
//! 1. the byte sizes, old encoding against new, and
//! 2. that the receiver's `(id, degree)` is the one that lands on the reconstructed share,
//!    whatever the sender did — the fields are unrepresentable on the wire, not merely checked.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use stoffelcrypto::common::gf2k::field::Gf256;
use stoffelcrypto::common::gf2k::share::{GfShare, GfShareWire};
use stoffelcrypto::common::math::goldilocks::GoldilocksField;
use stoffelcrypto::common::share::ShareError;
use stoffelcrypto::common::{ShamirShare, ShamirShareWire};
use stoffelcrypto::honeybadger::gf_mul::GfMultReconstructionMessage;
use stoffelcrypto::honeybadger::mul::ReconstructionMessage;
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

type F = GoldilocksField;

/// `Gf256` is one byte; `GoldilocksField` is eight. Both share types add `id: usize` +
/// `degree: usize` = 16 bytes under bincode fixint / `ark` `CanonicalSerialize`.
const GF_ELEM: usize = 1;
const F_ELEM: usize = 8;
const REDUNDANT_PER_SHARE: usize = 16;
/// Every `Vec`/`ShamirShareWire` body carries one `u64` count.
const COUNT_PREFIX: usize = 8;

fn gf_shares(m: usize, id: usize, degree: usize) -> Vec<GfShare<Gf256>> {
    (0..m)
        .map(|i| GfShare::new(Gf256((i % 255) as u8 + 1), id, degree))
        .collect()
}

fn f_shares(m: usize, id: usize, degree: usize) -> Vec<RobustShare<F>> {
    (0..m)
        .map(|i| RobustShare::new(F::from(i as u64 + 1), id, degree))
        .collect()
}

fn ark_bytes<T: CanonicalSerialize>(v: &T) -> Vec<u8> {
    let mut b = Vec::new();
    v.serialize_compressed(&mut b).unwrap();
    b
}

// ---------------------------------------------------------------- sizes

#[test]
fn share_wire_is_one_element_per_share_both_fields() {
    for m in [0usize, 1, 2, 4, 8, 16, 64, 695] {
        let old_gf = bincode::serialize(&gf_shares(m, 3, 2)).unwrap().len();
        let new_gf = bincode::serialize(&GfShareWire::encode(&gf_shares(m, 3, 2), 3, 2).unwrap())
            .unwrap()
            .len();
        let old_f = ark_bytes(&f_shares(m, 3, 2)).len();
        let new_f =
            ark_bytes(&ShamirShareWire::<F, 1>::encode(&f_shares(m, 3, 2), 3, 2).unwrap()).len();

        println!(
            "WIRE shares={m:<4} gf_old={old_gf:<6} gf_new={new_gf:<6} \
             f_old={old_f:<6} f_new={new_f:<6}"
        );

        assert_eq!(old_gf, COUNT_PREFIX + (GF_ELEM + REDUNDANT_PER_SHARE) * m);
        assert_eq!(new_gf, COUNT_PREFIX + GF_ELEM * m);
        assert_eq!(old_f, COUNT_PREFIX + (F_ELEM + REDUNDANT_PER_SHARE) * m);
        assert_eq!(new_f, COUNT_PREFIX + F_ELEM * m);
    }
}

#[test]
fn direct_open_messages_shed_thirty_two_bytes_per_multiplication() {
    // One `GfMultReconstructionMessage` / `ReconstructionMessage` carries two runs of `m` shares
    // (`a-x` and `b-y`), so the per-multiplication saving is twice the per-share saving.
    for m in [1usize, 2, 4, 8, 16, 64] {
        let gf = bincode::serialize(
            &GfMultReconstructionMessage::new(&gf_shares(m, 3, 2), &gf_shares(m, 3, 2), 3, 2)
                .unwrap(),
        )
        .unwrap()
        .len();
        let f = ark_bytes(
            &ReconstructionMessage::new(&f_shares(m, 3, 2), &f_shares(m, 3, 2), 3, 2).unwrap(),
        )
        .len();

        println!("WIRE mults={m:<3} gf_mult_recon={gf:<6} f_mult_recon={f:<6}");

        // Two bodies, each one count prefix plus its elements.
        assert_eq!(gf, 2 * (COUNT_PREFIX + GF_ELEM * m));
        assert_eq!(f, 2 * (COUNT_PREFIX + F_ELEM * m));
        // What the old encoding cost, for the record: 16 + 34m and 16 + 48m.
        assert_eq!(
            2 * (COUNT_PREFIX + (GF_ELEM + REDUNDANT_PER_SHARE) * m) - gf,
            2 * REDUNDANT_PER_SHARE * m
        );
    }
}

// ------------------------------------------------- derived, not trusted

#[test]
fn gf_wire_carries_no_id_and_no_degree() {
    // Two senders, two degrees, same elements. If either field were on the wire the bodies would
    // differ; they are byte-identical, which is what "unrepresentable" means here.
    let a = bincode::serialize(&GfShareWire::encode(&gf_shares(8, 0, 1), 0, 1).unwrap()).unwrap();
    let b = bincode::serialize(&GfShareWire::encode(&gf_shares(8, 9, 4), 9, 4).unwrap()).unwrap();
    assert_eq!(a, b, "the wire body must not depend on id or degree");

    let a = ark_bytes(&ShamirShareWire::<F, 1>::encode(&f_shares(8, 0, 1), 0, 1).unwrap());
    let b = ark_bytes(&ShamirShareWire::<F, 1>::encode(&f_shares(8, 9, 4), 9, 4).unwrap());
    assert_eq!(a, b, "the wire body must not depend on id or degree");
}

#[test]
fn decode_stamps_the_receivers_values_not_the_senders() {
    // The sender held shares at (id 9, degree 4). The receiver decodes at the pair IT derives —
    // authenticated sender 2, session threshold 1 — and that is what lands on every share.
    let wire = GfShareWire::encode(&gf_shares(5, 9, 4), 9, 4).unwrap();
    let round_tripped: GfShareWire<Gf256> =
        bincode::deserialize(&bincode::serialize(&wire).unwrap()).unwrap();
    for share in round_tripped.decode(2, 1) {
        assert_eq!(share.id, 2);
        assert_eq!(share.degree, 1);
    }

    let wire = ShamirShareWire::<F, 1>::encode(&f_shares(5, 9, 4), 9, 4).unwrap();
    let round_tripped =
        ShamirShareWire::<F, 1>::deserialize_compressed(ark_bytes(&wire).as_slice()).unwrap();
    for share in round_tripped
        .decode::<stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::Robust>(2, 1)
        .unwrap()
    {
        assert_eq!(share.id, 2);
        assert_eq!(share.degree, 1);
    }
}

#[test]
fn encode_refuses_a_batch_that_is_not_homogeneous() {
    // The sender states what it believes it is sending; a batch that mixes dealers or degrees is
    // a local bug and is refused here rather than silently flattened onto the receiver's
    // derivation.
    let mut mixed_id = gf_shares(4, 3, 2);
    mixed_id[2].id = 4;
    assert!(matches!(
        GfShareWire::encode(&mixed_id, 3, 2),
        Err(ShareError::IdMismatch)
    ));

    let mut mixed_degree = gf_shares(4, 3, 2);
    mixed_degree[1].degree = 5;
    assert!(matches!(
        GfShareWire::encode(&mixed_degree, 3, 2),
        Err(ShareError::DegreeMismatch)
    ));

    // Also refused when the batch is homogeneous but disagrees with the caller's claim.
    assert!(matches!(
        GfShareWire::encode(&gf_shares(4, 3, 2), 7, 2),
        Err(ShareError::IdMismatch)
    ));
    assert!(matches!(
        GfShareWire::encode(&gf_shares(4, 3, 2), 3, 9),
        Err(ShareError::DegreeMismatch)
    ));

    let mut mixed_id = f_shares(4, 3, 2);
    mixed_id[2].id = 4;
    assert!(matches!(
        ShamirShareWire::<F, 1>::encode(&mixed_id, 3, 2),
        Err(ShareError::IdMismatch)
    ));
    let mut mixed_degree = f_shares(4, 3, 2);
    mixed_degree[1].degree = 5;
    assert!(matches!(
        ShamirShareWire::<F, 1>::encode(&mixed_degree, 3, 2),
        Err(ShareError::DegreeMismatch)
    ));
}

#[test]
fn shamir_wire_rejects_a_body_that_is_not_a_whole_number_of_shares() {
    // The one shape a peer can still get wrong on the `F` side: `N > 1` packs `N` elements per
    // share, so an element count that is not a multiple of `N` is malformed.
    let shares: Vec<ShamirShare<F, 2, ()>> = (0..3)
        .map(|i| ShamirShare {
            share: [F::from(i as u64), F::from(i as u64 + 100)],
            id: 3,
            degree: 2,
            _sharetype: std::marker::PhantomData,
        })
        .collect();
    let wire = ShamirShareWire::<F, 2>::encode(&shares, 3, 2).unwrap();
    assert_eq!(wire.share_count(), Some(3));
    assert_eq!(wire.elements().len(), 6);

    // Same six elements read back as if they were `N = 2`... fine; as `N = 4`, not a whole
    // number of shares and rejected rather than truncated.
    let bytes = ark_bytes(&wire);
    let odd = ShamirShareWire::<F, 4>::deserialize_compressed(bytes.as_slice()).unwrap();
    assert_eq!(odd.share_count(), None);
    assert!(matches!(
        odd.decode::<()>(3, 2),
        Err(ShareError::InvalidInput)
    ));
}

#[test]
fn shamir_wire_bounded_read_rejects_a_peer_supplied_oversize_length() {
    // The length bound is the receiver's own (`max_shares`), never the peer's claim.
    let bytes = ark_bytes(&ShamirShareWire::<F, 1>::encode(&f_shares(16, 3, 2), 3, 2).unwrap());

    let mut r = bytes.as_slice();
    assert_eq!(
        ShamirShareWire::<F, 1>::deserialize_bounded(&mut r, 16)
            .unwrap()
            .share_count(),
        Some(16)
    );

    let mut r = bytes.as_slice();
    assert!(ShamirShareWire::<F, 1>::deserialize_bounded(&mut r, 15).is_err());
}

#[test]
fn direct_open_message_round_trips_through_the_receivers_derivation() {
    let a = gf_shares(3, 5, 2);
    let b = gf_shares(3, 5, 2);
    let msg = GfMultReconstructionMessage::new(&a, &b, 5, 2).unwrap();
    let wire: GfMultReconstructionMessage<Gf256> =
        bincode::deserialize(&bincode::serialize(&msg).unwrap()).unwrap();
    assert_eq!(wire.a_sub_x.len(), 3);
    let (da, db) = wire.into_shares(5, 2);
    assert_eq!(da, a);
    assert_eq!(db, b);

    let a = f_shares(3, 5, 2);
    let b = f_shares(3, 5, 2);
    let msg = ReconstructionMessage::new(&a, &b, 5, 2).unwrap();
    let wire =
        ReconstructionMessage::<F>::deserialize_compressed(ark_bytes(&msg).as_slice()).unwrap();
    let (da, db) = wire.into_shares(5, 2).unwrap();
    assert_eq!(da, a);
    assert_eq!(db, b);
}
