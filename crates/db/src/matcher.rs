use crate::irange::IRange;

pub trait DimMatcher<T> {
    fn match_scalar(&self, scalar: T) -> bool;
    fn match_range(&self, range: IRange<T>) -> bool;
}

macro_rules! impl_matcher {
    ($ty:ty) => {
        /// Match against a single element
        impl DimMatcher<$ty> for $ty {
            fn match_scalar(&self, scalar: $ty) -> bool {
                *self == scalar
            }
            fn match_range(&self, range: IRange<$ty>) -> bool {
                range.contains(*self)
            }
        }

        /// Match against a range of element
        impl DimMatcher<$ty> for IRange<$ty> {
            fn match_scalar(&self, scalar: $ty) -> bool {
                self.contains(scalar)
            }
            fn match_range(&self, range: IRange<$ty>) -> bool {
                !self.is_disjoint(&range)
            }
        }

        /// Match against a list of elements
        impl DimMatcher<$ty> for &'_ [$ty] {
            fn match_scalar(&self, scalar: $ty) -> bool {
                self.contains(&scalar)
            }
            fn match_range(&self, range: IRange<$ty>) -> bool {
                self.iter().any(|&item| range.contains(item))
            }
        }
    };
}

impl_matcher!(u32);
impl_matcher!(u64);
