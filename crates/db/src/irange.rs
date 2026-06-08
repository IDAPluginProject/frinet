use core::fmt;
use std::ops::{Add, Sub};

/// Inclusive Range
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IRange<S> {
    /// Inclusive minimum value
    pub min: S,
    /// Inclusive maximum value
    pub max: S,
}

#[cfg(feature = "arbitrary")]
impl<'a, S> arbitrary::Arbitrary<'a> for IRange<S>
where
    S: arbitrary::Arbitrary<'a> + Ord + Copy,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let a: S = u.arbitrary()?;
        let b: S = u.arbitrary()?;

        let min = core::cmp::min(a, b);
        let max = core::cmp::max(a, b);

        Ok(Self { min, max })
    }
}

impl<S: Scalar> IRange<S> {
    /// Create range with inclusive start and end
    pub fn new(min: S, max: S) -> Self {
        debug_assert!(min <= max);
        Self { min, max }
    }

    /// Build a range spanning over the entier value space
    pub fn full() -> Self {
        Self {
            min: S::ZERO,
            max: S::MAX,
        }
    }

    /// Build a range over only one value
    pub fn one(value: S) -> Self {
        Self {
            min: value,
            max: value,
        }
    }

    pub fn min_distance(&self, value: S) -> S {
        if value < self.min {
            self.min - value
        } else if self.max < value {
            value - self.max
        } else {
            S::ZERO
        }
    }

    pub fn contains(&self, value: S) -> bool {
        self.min <= value && value <= self.max
    }

    /// Return the intersection between two range
    pub fn intersection(&self, other: &Self) -> Option<Self> {
        debug_assert!(self.min <= self.max);
        debug_assert!(other.min <= other.max);

        if other.min > self.max {
            return None;
        }
        if self.min > other.max {
            return None;
        }

        let min = self.min.max(other.min);
        let max = self.max.min(other.max);
        Some(IRange::new(min, max))
    }

    #[allow(unused)]
    fn check_invariant(&self) {
        assert!(self.min <= self.max);
    }

    #[inline]
    pub fn is_disjoint(&self, other: &Self) -> bool {
        #[cfg(debug_assertions)]
        {
            self.check_invariant();
            other.check_invariant();
        }

        let a = self.max < other.min;
        let b = self.min > other.max;
        a || b
    }

    /// Create range with (start, length)
    pub fn from_start_len(start: S, len: S) -> Self {
        assert!(len > S::ZERO);
        let min = start;
        let max = start + (len - S::ONE);

        Self { min, max }
    }

    /// Number of unique values included in this range
    pub fn span(&self) -> S {
        (self.max - self.min)
            .checked_add(S::ONE)
            .expect("span value is not representable")
    }

    /// Number of unique values included in this range
    pub fn span_usize(&self) -> usize {
        let min = self.min.into_usize();
        let max = self.max.into_usize();
        (max - min)
            .checked_add(1)
            .expect("span_usize value is not representable")
    }

    /// Number of bits required to represent every values in this range
    pub fn span_bits(&self) -> u32 {
        let diff = self.max - self.min;
        diff.checked_ilog2().unwrap_or(0) + 1
    }
}

impl<T> fmt::Display for IRange<T>
where
    T: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..={}", self.min, self.max)
    }
}

impl<T> fmt::Debug for IRange<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}..={:?}", self.min, self.max)
    }
}

impl<T> fmt::LowerHex for IRange<T>
where
    T: fmt::LowerHex,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "{:#x}..={:#x}", self.min, self.max)
        } else {
            write!(f, "{:x}..={:x}", self.min, self.max)
        }
    }
}

pub trait Scalar: Copy + Ord + Add<Output = Self> + Sub<Output = Self> {
    const ZERO: Self;
    const ONE: Self;
    const MAX: Self;
    const BITS: u32;

    fn checked_ilog2(self) -> Option<u32>;

    /// Panic if the value is too big to fit in usize
    fn into_usize(self) -> usize;

    /// Checked add
    fn checked_add(self, other: Self) -> Option<Self>;
}

macro_rules! impl_scalar_for_std_unsigned {
    ($ty:ty) => {
        impl Scalar for $ty {
            const ZERO: Self = 0;
            const ONE: Self = 1;
            const MAX: Self = Self::MAX;
            const BITS: u32 = Self::BITS;

            fn checked_add(self, other: Self) -> Option<Self> {
                <$ty>::checked_add(self, other)
            }

            fn checked_ilog2(self) -> Option<u32> {
                <$ty>::checked_ilog2(self)
            }

            fn into_usize(self) -> usize {
                self.try_into().unwrap()
            }
        }
    };
}

impl_scalar_for_std_unsigned!(u8);
impl_scalar_for_std_unsigned!(u16);
impl_scalar_for_std_unsigned!(u32);
impl_scalar_for_std_unsigned!(u64);
impl_scalar_for_std_unsigned!(u128);
