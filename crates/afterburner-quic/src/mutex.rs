use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};

/// A Mutex that takes the purpose of each lock, kept for call-site compatibility
#[derive(Debug)]
pub(crate) struct Mutex<T> {
    inner: std::sync::Mutex<T>,
}

impl<T> Mutex<T> {
    pub(crate) fn new(value: T) -> Self {
        Self {
            inner: std::sync::Mutex::new(value),
        }
    }

    /// Acquires the lock; a poisoned lock is taken over, as the state it guards stays consistent
    pub(crate) fn lock(&self, _purpose: &'static str) -> MutexGuard<'_, T> {
        MutexGuard {
            guard: self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        }
    }
}

pub(crate) struct MutexGuard<'a, T> {
    guard: std::sync::MutexGuard<'a, T>,
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.guard.deref()
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guard.deref_mut()
    }
}
