use std::cmp::min;

#[derive(Debug)]
pub struct DequeSliceMut<'a, T> {
    pub front: &'a mut [T],
    pub back: &'a mut [T],
}

impl<'a, T> DequeSliceMut<'a, T> {
    pub fn new(front: &'a mut [T], back: &'a mut [T]) -> Self {
        Self { front, back }
    }

    pub fn mt() -> Self {
        Self {
            front: &mut [],
            back: &mut [],
        }
    }

    pub fn from_slice_mut_start_at(slice: &'a mut [T], index: usize) -> Self {
        let (back, front) = slice.split_at_mut(index);

        Self { front, back }
    }

    pub fn copy_from_slice(&mut self, src: &[T])
    where
        T: Copy,
    {
        assert_eq!(self.len(), src.len());

        let (src_front, src_back) = src.split_at(self.front.len());
        self.front.copy_from_slice(src_front);
        self.back.copy_from_slice(src_back);
    }

    pub fn copy(&mut self, src: &[T]) -> usize
    where
        T: Copy,
    {
        let front_len = min(self.front.len(), src.len());
        let (src_front, src_back) = src.split_at(front_len);
        let back_len = min(src_back.len(), self.back.len());
        self.front[..front_len].copy_from_slice(src_front);
        self.back[..back_len].copy_from_slice(src_back);

        front_len + back_len
    }

    pub fn len(&self) -> usize {
        self.front.len() + self.back.len()
    }

    pub fn is_empty(&self) -> bool {
        self.front.is_empty() && self.back.is_empty()
    }

    pub fn split_mut(self, index: usize) -> (Self, Self) {
        assert!(index <= self.len());

        // Indices for the left side
        let front_len1 = min(self.front.len(), index);
        let back_len1 = index - front_len1;

        let (front1, front2) = self.front.split_at_mut(front_len1);
        let (back1, back2) = self.back.split_at_mut(back_len1);

        (Self::new(front1, back1), Self::new(front2, back2))
    }

    pub fn to_immutable(self) -> DequeSlice<'a, T> {
        DequeSlice::new(self.front, self.back)
    }
}

pub struct DequeSlice<'a, T> {
    pub front: &'a [T],
    pub back: &'a [T],
}

impl<'a, T> DequeSlice<'a, T> {
    pub fn new(front: &'a [T], back: &'a [T]) -> Self {
        Self { front, back }
    }
}
