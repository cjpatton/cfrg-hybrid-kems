//! Implementation of draft-irtf-cfrg-cfrg-hybrid-kems based on PR #72.

use rand::random;
use std::marker::PhantomData;

macro_rules! combine {
    ($n:ident, $kem:ident, $derive:ident, $pq_ss:expr, $t_ss:expr, $ct:expr, $ek:expr, $label:expr) => {{
        let mut kdf_state = $derive::init_kdf();
        kdf_state.update($pq_ss);
        kdf_state.update($t_ss);
        if $kem::IMPLICIT_COMBINER_ALLOWED {
            UpdateKdfState::<$n>::update(&$ct.t, &mut kdf_state);
            UpdateKdfState::<$n>::update(&$ek.t, &mut kdf_state);
        } else {
            UpdateKdfState::<$n>::update($ct, &mut kdf_state);
            UpdateKdfState::<$n>::update($ek, &mut kdf_state);
        }
        kdf_state.update($label);
        kdf_state.finalize()
    }};
}

pub trait Derive<const N: usize> {
    type State: KdfState<N>;
    fn init_kdf() -> Self::State;
    fn prg(seed: [u8; N]) -> [[u8; N]; 2];
}

pub trait KdfState<const N: usize> {
    fn update(&mut self, input: &[u8]);
    fn finalize(&self) -> [u8; N];
}

pub trait UpdateKdfState<const N: usize> {
    fn update(&self, kdf_state: &mut impl KdfState<N>);
}

pub trait Kem<const N: usize> {
    type EncapsKey: UpdateKdfState<N>;
    type DecapsKey;
    type Ciphertext: UpdateKdfState<N>;
    fn derive_key_pair(&self, seed: [u8; N]) -> (Self::EncapsKey, Self::DecapsKey);
    fn encaps(&self, ek: &Self::EncapsKey) -> (Self::Ciphertext, [u8; N]);
    fn decaps(&self, dk: &Self::DecapsKey, ciphertext: &Self::Ciphertext) -> [u8; N];

    fn generate_key_pair(&self) -> (Self::EncapsKey, Self::DecapsKey) {
        self.derive_key_pair(random())
    }
}

pub trait KemWithProperties<const N: usize>: Kem<N> {
    /// Indicates whether the KEM is C2PRI-secure.
    const IMPLICIT_COMBINER_ALLOWED: bool;
}

pub trait Group<const N: usize> {
    const GENERATOR: Self::Element;
    type Element: UpdateKdfState<N>;
    type Scalar;
    fn exp(element: &Self::Element, scalar: &Self::Scalar) -> Self::Element;
    fn random_scalar(seed: [u8; N]) -> Self::Scalar;
    fn element_to_shared_secret(element: &Self::Element) -> [u8; N];
}

/// KX, KM
pub struct HybridWithKem<const N: usize, PQ: KemWithProperties<N>, T: Kem<N>, H: Derive<N>> {
    label: &'static [u8],
    pq: PQ,
    t: T,
    phantom: PhantomData<H>,
}

impl<const N: usize, PQ: KemWithProperties<N>, T: Kem<N>, H: Derive<N>> HybridWithKem<N, PQ, T, H> {
    pub fn new(label: &'static [u8], pq: PQ, t: T) -> Self {
        Self {
            label,
            pq,
            t,
            phantom: PhantomData,
        }
    }
}

impl<const N: usize, PQ: KemWithProperties<N>, T: Kem<N>, H: Derive<N>> Kem<N>
    for HybridWithKem<N, PQ, T, H>
where
    PQ::EncapsKey: Clone,
    T::EncapsKey: Clone,
{
    type EncapsKey = HybridEncapsKeyWithKem<N, PQ, T>;
    type DecapsKey = HybridDecapsKeyWithKem<N, PQ, T>;
    type Ciphertext = HybridCiphertextWithKem<N, PQ, T>;

    fn derive_key_pair(&self, seed: [u8; N]) -> (Self::EncapsKey, Self::DecapsKey) {
        let [pq_seed, t_seed] = H::prg(seed);
        let (pq_ek, pq_dk) = self.pq.derive_key_pair(pq_seed);
        let (t_ek, t_dk) = self.t.derive_key_pair(t_seed);
        (
            HybridEncapsKeyWithKem {
                pq: pq_ek.clone(),
                t: t_ek.clone(),
            },
            HybridDecapsKeyWithKem {
                pq: pq_dk,
                t: t_dk,
                ek: HybridEncapsKeyWithKem { pq: pq_ek, t: t_ek },
            },
        )
    }

    fn encaps(&self, ek: &Self::EncapsKey) -> (Self::Ciphertext, [u8; N]) {
        let (pq_ct, pq_ss) = self.pq.encaps(&ek.pq);
        let (t_ct, t_ss) = self.t.encaps(&ek.t);
        let ct = HybridCiphertextWithKem { pq: pq_ct, t: t_ct };
        let ss = combine!(N, PQ, H, &pq_ss, &t_ss, &ct, ek, self.label);
        (ct, ss)
    }

    fn decaps(&self, dk: &Self::DecapsKey, ct: &Self::Ciphertext) -> [u8; N] {
        let pq_ss = self.pq.decaps(&dk.pq, &ct.pq);
        let t_ss = self.t.decaps(&dk.t, &ct.t);
        combine!(N, PQ, H, &pq_ss, &t_ss, ct, &dk.ek, self.label)
    }
}

pub struct HybridEncapsKeyWithKem<const N: usize, PQ: KemWithProperties<N>, T: Kem<N>> {
    pq: PQ::EncapsKey,
    t: T::EncapsKey,
}

impl<const N: usize, PQ: KemWithProperties<N>, T: Kem<N>> UpdateKdfState<N>
    for HybridEncapsKeyWithKem<N, PQ, T>
{
    fn update(&self, kdf_state: &mut impl KdfState<N>) {
        self.pq.update(kdf_state);
        self.t.update(kdf_state);
    }
}

pub struct HybridDecapsKeyWithKem<const N: usize, PQ: KemWithProperties<N>, T: Kem<N>> {
    pq: PQ::DecapsKey,
    t: T::DecapsKey,
    ek: HybridEncapsKeyWithKem<N, PQ, T>,
}

pub struct HybridCiphertextWithKem<const N: usize, PQ: KemWithProperties<N>, T: Kem<N>> {
    pq: PQ::Ciphertext,
    t: T::Ciphertext,
}

impl<const N: usize, PQ: KemWithProperties<N>, T: Kem<N>> UpdateKdfState<N>
    for HybridCiphertextWithKem<N, PQ, T>
{
    fn update(&self, kdf_state: &mut impl KdfState<N>) {
        self.pq.update(kdf_state);
        self.t.update(kdf_state);
    }
}

/// GX, GM
pub struct HybridWithGroup<const N: usize, PQ: KemWithProperties<N>, T: Group<N>, H: Derive<N>> {
    label: &'static [u8],
    pq: PQ,
    phantom: PhantomData<(T, H)>,
}

impl<const N: usize, PQ: KemWithProperties<N>, T: Group<N>, H: Derive<N>>
    HybridWithGroup<N, PQ, T, H>
{
    pub fn new(label: &'static [u8], pq: PQ) -> Self {
        Self {
            label,
            pq,
            phantom: PhantomData,
        }
    }
}

impl<const N: usize, PQ: KemWithProperties<N>, T: Group<N>, H: Derive<N>> Kem<N>
    for HybridWithGroup<N, PQ, T, H>
where
    PQ::EncapsKey: Clone,
    T::Element: Clone,
{
    type EncapsKey = HybridEncapsKeyWithGroup<N, PQ, T>;
    type DecapsKey = HybridDecapsKeyWithGroup<N, PQ, T>;
    type Ciphertext = HybridCiphertextWithGroup<N, PQ, T>;

    fn derive_key_pair(&self, seed: [u8; N]) -> (Self::EncapsKey, Self::DecapsKey) {
        let [pq_seed, t_seed] = H::prg(seed);
        let (pq_ek, pq_dk) = self.pq.derive_key_pair(pq_seed);
        let t_dk = T::random_scalar(t_seed);
        let t_ek = T::exp(&T::GENERATOR, &t_dk);
        (
            HybridEncapsKeyWithGroup {
                pq: pq_ek.clone(),
                t: t_ek.clone(),
            },
            HybridDecapsKeyWithGroup {
                pq: pq_dk,
                t: t_dk,
                ek: HybridEncapsKeyWithGroup { pq: pq_ek, t: t_ek },
            },
        )
    }

    fn encaps(&self, ek: &Self::EncapsKey) -> (Self::Ciphertext, [u8; N]) {
        let (pq_ct, pq_ss) = self.pq.encaps(&ek.pq);
        let t_sk = T::random_scalar(random());
        let t_ct = T::exp(&T::GENERATOR, &t_sk);
        let t_ss = T::element_to_shared_secret(&T::exp(&ek.t, &t_sk));
        let ct = HybridCiphertextWithGroup { pq: pq_ct, t: t_ct };
        let ss = combine!(N, PQ, H, &pq_ss, &t_ss, &ct, ek, self.label);
        (ct, ss)
    }

    fn decaps(&self, dk: &Self::DecapsKey, ct: &Self::Ciphertext) -> [u8; N] {
        let pq_ss = self.pq.decaps(&dk.pq, &ct.pq);
        let t_ss = T::element_to_shared_secret(&T::exp(&ct.t, &dk.t));
        combine!(N, PQ, H, &pq_ss, &t_ss, ct, &dk.ek, self.label)
    }
}

pub struct HybridEncapsKeyWithGroup<const N: usize, PQ: KemWithProperties<N>, T: Group<N>> {
    pq: PQ::EncapsKey,
    t: T::Element,
}

impl<const N: usize, PQ: KemWithProperties<N>, T: Group<N>> UpdateKdfState<N>
    for HybridEncapsKeyWithGroup<N, PQ, T>
{
    fn update(&self, kdf_state: &mut impl KdfState<N>) {
        self.pq.update(kdf_state);
        self.t.update(kdf_state);
    }
}

pub struct HybridDecapsKeyWithGroup<const N: usize, PQ: KemWithProperties<N>, T: Group<N>> {
    pq: PQ::DecapsKey,
    t: T::Scalar,
    ek: HybridEncapsKeyWithGroup<N, PQ, T>,
}

pub struct HybridCiphertextWithGroup<const N: usize, PQ: KemWithProperties<N>, T: Group<N>> {
    pq: PQ::Ciphertext,
    t: T::Element,
}

impl<const N: usize, PQ: KemWithProperties<N>, T: Group<N>> UpdateKdfState<N>
    for HybridCiphertextWithGroup<N, PQ, T>
{
    fn update(&self, kdf_state: &mut impl KdfState<N>) {
        self.pq.update(kdf_state);
        self.t.update(kdf_state);
    }
}
