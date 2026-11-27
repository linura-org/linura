//! Historical ownership comparison after full directory-wide lineage checks.
//! This cannot reconstruct a live peer, authorization or physical completion.
use super::*;
use std::collections::BTreeSet;

#[derive(Default)]
struct SpentSuccessors(BTreeMap<String, String>);
impl SpentSuccessors {
    fn insert(&mut self, child: String, parent: &str) -> Result<(), String> {
        if self.0.len() >= MAX_RECORDS
            || child == parent
            || self.0.contains_key(&child)
            || self.0.values().any(|old| old == parent)
        {
            return Err(unavailable());
        }
        self.0.insert(child, parent.into());
        Ok(())
    }
    fn ancestors(&self, child: &str) -> Result<BTreeSet<String>, String> {
        let mut seen = BTreeSet::from([child.to_owned()]);
        let mut at = child;
        while let Some(parent) = self.0.get(at) {
            if !seen.insert(parent.clone()) || seen.len() > MAX_RECORDS {
                return Err(unavailable());
            }
            at = parent;
        }
        Ok(seen)
    }
    fn validate(&self) -> Result<(), String> {
        for child in self.0.keys() {
            self.ancestors(child)?;
        }
        Ok(())
    }
    fn related(&self, left: &str, right: &str) -> Result<bool, String> {
        // Sharing some ancestor is insufficient: competing siblings are never
        // an ordered transfer, even if their historical bytes both validate.
        Ok(left != right
            && (self.ancestors(left)?.contains(right) || self.ancestors(right)?.contains(left)))
    }
}

impl TerminalLineage {
    pub(super) fn verify_supersession_ownership(&self) -> Result<(), String> {
        let mut spent = SpentSuccessors::default();
        for record in self.ordinary_successor_spent.values() {
            spent.insert(
                record.binding().dispatch_digest.to_hex(),
                record
                    .parent()
                    .parent()
                    .frames()
                    .scope()
                    .original_dispatch(),
            )?;
        }
        for record in self.successor_spent.values() {
            spent.insert(
                record.binding().dispatch_digest.to_hex(),
                record
                    .parent()
                    .parent()
                    .frames()
                    .scope()
                    .original_dispatch(),
            )?;
        }
        spent.validate()?;
        let mut owners = Vec::new();
        for (dispatch, record) in &self.ordinary_releases {
            owners.push((
                dispatch.clone(),
                record.decoded_material()?.original().topology().clone(),
            ));
        }
        for record in self.restorations.values() {
            let material = record.decoded_material()?;
            owners.push((
                material.original_dispatch().to_owned(),
                material.replacement().topology().clone(),
            ));
        }
        for (index, (left, topology)) in owners.iter().enumerate() {
            for (right, other) in &owners[index + 1..] {
                if left == right
                    || topology.session().boot() == other.session().boot()
                        && topology.session().uid() == other.session().uid()
                        && topology.seat() == other.seat()
                        && !spent.related(left, right)?
                {
                    return Err(unavailable());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_ordered_spent_ancestry_can_supersede_retained_owners() {
        let mut chain = SpentSuccessors::default();
        chain
            .insert("second".into(), "first")
            .unwrap_or_else(|e| unreachable!("{e}"));
        chain
            .insert("third".into(), "second")
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(
            chain
                .related("third", "first")
                .unwrap_or_else(|e| unreachable!("{e}"))
        );
        assert!(
            chain
                .related("first", "second")
                .unwrap_or_else(|e| unreachable!("{e}"))
        );
        assert!(
            !chain
                .related("first", "first")
                .unwrap_or_else(|e| unreachable!("{e}"))
        );
        assert!(
            !chain
                .related("other", "third")
                .unwrap_or_else(|e| unreachable!("{e}"))
        );
        assert!(chain.insert("sibling".into(), "first").is_err());
        assert!(chain.insert("third".into(), "other").is_err());
        assert!(chain.insert("self".into(), "self").is_err());
        chain
            .insert("first".into(), "third")
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(chain.validate().is_err());
        assert!(chain.related("third", "first").is_err());
    }
}
