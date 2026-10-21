//! Serial in-memory reservation service. No external-I/O rollback or durability.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    pub total: u64,
    pub available: u64,
    pub reservations: BTreeMap<String, u64>,
}

impl Inventory {
    pub fn new(total: u64) -> Self {
        Self {
            total,
            available: total,
            reservations: BTreeMap::new(),
        }
    }
    pub fn reserve(&mut self, id: &str, quantity: u64, fault: bool) -> &'static str {
        if quantity == 0 || quantity > self.available || self.reservations.contains_key(id) {
            return "reject";
        }
        let mut candidate = self.clone();
        candidate.available -= quantity;
        candidate.reservations.insert(id.into(), quantity);
        if fault {
            return "abort";
        }
        if !candidate.valid() {
            return "reject";
        }
        *self = candidate;
        "commit"
    }
    pub fn cancel(&mut self, id: &str) -> &'static str {
        let mut candidate = self.clone();
        let Some(quantity) = candidate.reservations.remove(id) else {
            return "reject";
        };
        candidate.available += quantity;
        if !candidate.valid() {
            return "reject";
        }
        *self = candidate;
        "commit"
    }
    pub fn valid(&self) -> bool {
        self.reservations
            .values()
            .try_fold(self.available, |a, q| a.checked_add(*q))
            == Some(self.total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reservation_sequences_and_candidate_failure() {
        let mut state = Inventory::new(10);
        assert_eq!(state.reserve("a", 6, false), "commit");
        let before = state.clone();
        assert_eq!(state.reserve("a", 1, false), "reject");
        assert_eq!(state.reserve("b", 5, false), "reject");
        assert_eq!(state.reserve("b", 2, true), "abort");
        assert_eq!(before, state);
        assert_eq!(state.cancel("a"), "commit");
        assert_eq!(state.cancel("a"), "reject");
        assert!(state.valid());
        assert_eq!(state.available, 10);
    }
}
