//! ACL set-operations, ported from FreeBSD `setfacl` and adapted to the
//! one Windows constraint that matters: an explicit entry may not claim to
//! be inherited, and the explicit section must sort deny-before-allow.

use crate::model::{Ace, AceType, INHERITED_ACE, INHERIT_FLAGS, INHERIT_ONLY_ACE};

/// Splits a full ACL (in stored order) into (explicit, inherited).
///
/// The split is the load-bearing detail: on Windows an inherited ACE is
/// read-only, so every operation below works on the explicit section and
/// the inherited one is carried around untouched.
pub fn split_inherited(acl: &[Ace]) -> (Vec<Ace>, Vec<Ace>) {
    let mut explicit = Vec::new();
    let mut inherited = Vec::new();
    for ace in acl {
        if ace.is_inherited() {
            inherited.push(ace.clone());
        } else {
            explicit.push(ace.clone());
        }
    }
    (explicit, inherited)
}

/// `setfacl -m` / `-M`: merge `new` into the explicit section.
///
/// Mirrors FreeBSD `merge_acl`:
///
/// - Match key is trustee + type; flags and mask are NOT compared.
/// - Every match is updated in place (FreeBSD keeps scanning after a
///   match, so duplicate entries all get the new mask and flags).
/// - An unmatched entry is inserted at the front, at a position that
///   grows by one per new entry — that is what keeps
///   `-m user:1:r:allow,user:2:r:allow` in input order instead of
///   reversing it.
///
/// Windows deviations, per ACL-PORT-SPEC §3/§4.1:
///
/// - An input entry marked INHERITED describes an inherited ACE (that is
///   what round-tripped `getfacl` output looks like). Such an entry can
///   never be applied: if it matches an inherited ACE exactly it is a
///   no-op (this is what makes `getfacl | setfacl -M -` a fixed point);
///   anything else is a loud refusal — inherited ACEs are read-only.
/// - For plain explicit entries the INHERITED bit is stripped from
///   whatever the user wrote: only Windows gets to call an ACE inherited.
pub fn merge(new: &[Ace], explicit: &mut Vec<Ace>, inherited: &[Ace]) -> Result<(), String> {
    let mut insert_at = 0usize;
    for ace in new {
        if ace.is_inherited() {
            let twin = inherited.iter().find(|e| e.same_key(ace));
            match twin {
                Some(t) if t.mask == ace.mask && t.flags == ace.flags => continue,
                Some(_) => {
                    return Err(
                        "entry is inherited from the parent directory and read-only; \
                         modify the parent, or break inheritance first"
                            .into(),
                    )
                }
                None => {
                    return Err(
                        "input entry is marked inherited but no inherited ACE matches it"
                            .into(),
                    )
                }
            }
        }
        let mut matched = false;
        for e in explicit.iter_mut() {
            if e.same_key(ace) {
                e.mask = ace.mask;
                e.flags = ace.flags & !INHERITED_ACE;
                matched = true;
            }
        }
        if !matched {
            let mut inserted = ace.clone();
            inserted.flags &= !INHERITED_ACE;
            explicit.insert(insert_at, inserted);
            insert_at += 1;
        }
    }
    canonical_sort(explicit);
    Ok(())
}

/// `setfacl -x <entries>`: remove the first entry matching each spec
/// entry, in spec order. Returns the specs that matched nothing, so the
/// caller can tell "no such entry" from "the match is inherited" (the
/// honest version of what `icacls /remove` silently ignores).
pub fn remove<'a>(spec: &'a [Ace], explicit: &mut Vec<Ace>) -> Vec<&'a Ace> {
    let mut missed = Vec::new();
    for want in spec {
        let pos = explicit.iter().position(|e| e.same_key(want));
        match pos {
            Some(i) => {
                explicit.remove(i);
            }
            None => missed.push(want),
        }
    }
    missed
}

/// `setfacl -x <n>`: remove by position, numbered over the FULL displayed
/// ACL (explicit then inherited). The caller resolves the number against
/// the split sections and refuses positions that land on inherited
/// entries.
pub fn remove_by_number(n: usize, explicit: &mut Vec<Ace>) -> bool {
    if n < explicit.len() {
        explicit.remove(n);
        true
    } else {
        false
    }
}

/// `setfacl -b`: remove all explicit entries, leaving a purely inherited
/// ACL. FreeBSD strips to a trivial ACL; the Windows mental model is
/// "undo every explicit change", so v1 keeps only what was inherited.
///
/// Clearing here can legitimately produce an empty list mid-queue —
/// `-b -M file` rebuilds afterwards. The guard against writing an
/// actually-empty DACL lives at the write step, on the FINAL state.
pub fn remove_all_explicit(explicit: &mut Vec<Ace>) {
    explicit.clear();
}

/// Windows canonical order inside the explicit section: deny entries
/// before allow entries, order otherwise preserved (stable).
///
/// Evaluation on Windows is strictly first-match, so a deny after an
/// allow-everything never fires; sorting denies to the front is what makes
/// `-m ...:deny` behave the way the reader of the script expects. FreeBSD
/// needs no such step because prepend-at-zero already puts new entries
/// ahead of everything.
pub fn canonical_sort(explicit: &mut [Ace]) {
    explicit.sort_by_key(|e| e.kind != AceType::Deny);
}

/// `setfacl -R` on a non-directory: strip the inheritance flags from the
/// pending entries so a file is never assigned its parent directory's
/// inherit-only entries.
///
/// Ported from FreeBSD `clear_inheritance_flags`:
/// 1. drop every entry with `INHERIT_ONLY`;
/// 2. clear `f`, `d`, `n` from the rest (`i` is covered by rule 1).
///
/// Leaving these in would create the contradictory state "explicitly set
/// AND claims to be inherited".
pub fn clear_inheritance_flags(new: &[Ace]) -> Vec<Ace> {
    new.iter()
        .filter(|a| a.flags & INHERIT_ONLY_ACE == 0)
        .map(|a| Ace {
            trustee: a.trustee.clone(),
            kind: a.kind,
            mask: a.mask,
            flags: a.flags & !INHERIT_FLAGS,
        })
        .collect()
}

/// `setfacl -a <position> <entries>`: insert at the given position of the
/// explicit section, shifting the rest; multiple entries keep input order.
/// The result is canonicalised afterwards, so the effective position of a
/// deny entry may end up earlier than requested — on Windows the DACL
/// order is a correctness constraint, not just a preference.
pub fn insert_at(position: usize, new: &[Ace], explicit: &mut Vec<Ace>) -> Result<(), String> {
    if position > explicit.len() {
        return Err(format!(
            "position {position} is beyond the end of the ACL ({} entries)",
            explicit.len()
        ));
    }
    let mut at = position;
    for ace in new {
        explicit.insert(at, ace.clone());
        at += 1;
    }
    canonical_sort(explicit);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Ace, AceType, Trustee, INHERIT_ONLY_ACE, OBJECT_INHERIT_ACE,
        CONTAINER_INHERIT_ACE, INHERITED_ACE, NO_PROPAGATE_INHERIT_ACE};

    fn user(sid: &str, kind: AceType, mask: u32) -> Ace {
        Ace { trustee: Trustee::User(sid.into()), kind, mask, flags: 0 }
    }

    fn owner(kind: AceType, mask: u32) -> Ace {
        Ace { trustee: Trustee::Owner, kind, mask, flags: 0 }
    }

    #[test]
    fn merge_updates_matching_and_prepends_new() {
        let mut explicit = vec![user("S-1", AceType::Allow, 1)];
        merge(&[user("S-1", AceType::Allow, 2)], &mut explicit, &[]).unwrap();
        assert_eq!(explicit[0].mask, 2);
        assert_eq!(explicit.len(), 1);

        merge(&[user("S-2", AceType::Allow, 4)], &mut explicit, &[]).unwrap();
        assert_eq!(explicit[0].trustee, Trustee::User("S-2".into()));
        assert_eq!(explicit[1].trustee, Trustee::User("S-1".into()));
    }

    #[test]
    fn merge_key_includes_type_but_not_flags() {
        // An allow never merges into a deny of the same trustee.
        let mut explicit = vec![user("S-1", AceType::Deny, 1)];
        merge(&[user("S-1", AceType::Allow, 2)], &mut explicit, &[]).unwrap();
        assert_eq!(explicit.len(), 2);
        assert_eq!(explicit[0].kind, AceType::Deny);
        assert_eq!(explicit[1].kind, AceType::Allow);
    }

    #[test]
    fn merge_updates_every_duplicate() {
        // FreeBSD keeps scanning after a match, so duplicates all receive
        // the new mask.
        let mut explicit = vec![user("S-1", AceType::Allow, 1), user("S-1", AceType::Allow, 2)];
        merge(&[user("S-1", AceType::Allow, 9)], &mut explicit, &[]).unwrap();
        assert_eq!(explicit[0].mask, 9);
        assert_eq!(explicit[1].mask, 9);
    }

    #[test]
    fn merge_within_one_option_collapses_duplicates() {
        // The second entry sees the first one's insertion and updates it,
        // exactly as FreeBSD's inner loop scans the mutated ACL.
        let mut explicit = vec![owner(AceType::Allow, 1)];
        merge(
            &[user("S-1", AceType::Allow, 2), user("S-1", AceType::Allow, 3)],
            &mut explicit,
            &[],
        )
        .unwrap();
        assert_eq!(explicit.len(), 2);
        assert_eq!(explicit[0].trustee, Trustee::User("S-1".into()));
        assert_eq!(explicit[0].mask, 3);
    }

    #[test]
    fn merge_orders_deny_before_allow() {
        let mut explicit = vec![user("S-1", AceType::Allow, 1)];
        merge(&[user("S-2", AceType::Deny, 2)], &mut explicit, &[]).unwrap();
        assert_eq!(explicit[0].kind, AceType::Deny);
        assert_eq!(explicit[1].kind, AceType::Allow);
    }

    #[test]
    fn multiple_new_entries_keep_input_order() {
        let mut explicit = vec![owner(AceType::Allow, 1)];
        merge(
            &[user("S-1", AceType::Allow, 1), user("S-2", AceType::Allow, 1)],
            &mut explicit,
            &[],
        )
        .unwrap();
        // New entries sit at the front, first-newest before second-newest.
        assert_eq!(explicit[0].trustee, Trustee::User("S-1".into()));
        assert_eq!(explicit[1].trustee, Trustee::User("S-2".into()));
        assert_eq!(explicit[2].trustee, Trustee::Owner);
    }

    #[test]
    fn remove_takes_the_first_match_per_spec() {
        let mut explicit = vec![user("S-1", AceType::Allow, 1), user("S-1", AceType::Allow, 2)];
        let spec = [user("S-1", AceType::Allow, 0)];
        let missed = remove(&spec, &mut explicit);
        assert!(missed.is_empty());
        assert_eq!(explicit.len(), 1);
        assert_eq!(explicit[0].mask, 2);
    }

    #[test]
    fn remove_reports_misses() {
        let mut explicit = vec![user("S-1", AceType::Allow, 1)];
        let spec = [user("S-9", AceType::Allow, 1)];
        let missed = remove(&spec, &mut explicit);
        assert_eq!(missed.len(), 1);
        assert_eq!(explicit.len(), 1);
    }

    #[test]
    fn remove_by_number_deletes_and_reports() {
        let mut explicit = vec![owner(AceType::Allow, 1), user("S-1", AceType::Allow, 1)];
        assert!(remove_by_number(0, &mut explicit));
        assert_eq!(explicit[0].trustee, Trustee::User("S-1".into()));
        assert!(!remove_by_number(5, &mut explicit));
    }

    #[test]
    fn strip_inheritance_flags_drops_inherit_only() {
        let a = Ace { trustee: Trustee::Owner, kind: AceType::Allow, mask: 1,
            flags: OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE };
        let b = Ace { trustee: Trustee::Everyone, kind: AceType::Allow, mask: 1,
            flags: CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE };
        let out = clear_inheritance_flags(&[a, b]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].flags, 0);
    }

    #[test]
    fn canonical_sort_is_stable() {
        let mut aces = vec![user("S-1", AceType::Allow, 1), user("S-2", AceType::Deny, 1),
            user("S-3", AceType::Allow, 1), user("S-4", AceType::Deny, 1)];
        canonical_sort(&mut aces);
        assert_eq!(aces[0].trustee, Trustee::User("S-2".into()));
        assert_eq!(aces[1].trustee, Trustee::User("S-4".into()));
        assert_eq!(aces[2].trustee, Trustee::User("S-1".into()));
        assert_eq!(aces[3].trustee, Trustee::User("S-3".into()));
    }

    #[test]
    fn insert_at_shifts_and_keeps_order() {
        let mut explicit = vec![owner(AceType::Allow, 1)];
        insert_at(0, &[user("S-1", AceType::Allow, 1), user("S-2", AceType::Allow, 1)],
            &mut explicit).unwrap();
        assert_eq!(explicit[0].trustee, Trustee::User("S-1".into()));
        assert_eq!(explicit[1].trustee, Trustee::User("S-2".into()));
        assert_eq!(explicit[2].trustee, Trustee::Owner);
        assert!(insert_at(9, &[], &mut explicit).is_err());
    }

    #[test]
    fn b_clears_the_explicit_section() {
        let mut explicit = vec![owner(AceType::Allow, 1)];
        remove_all_explicit(&mut explicit);
        assert!(explicit.is_empty());
    }

    #[test]
    fn inherited_input_matching_exactly_is_a_no_op() {
        // The fixed-point rule: getfacl output fed back through -M must
        // not duplicate the inherited entries it lists.
        let mut twin = user("S-1", AceType::Allow, 7);
        twin.flags = INHERITED_ACE;
        let mut explicit = vec![owner(AceType::Allow, 1)];
        merge(&[twin.clone()], &mut explicit, &[twin]).unwrap();
        assert_eq!(explicit.len(), 1, "nothing may be added");
    }

    #[test]
    fn inherited_input_trying_to_change_is_refused() {
        let mut twin = user("S-1", AceType::Allow, 7);
        twin.flags = INHERITED_ACE;
        let mut changed = twin.clone();
        changed.mask = 9;
        let mut explicit = vec![owner(AceType::Allow, 1)];
        assert!(merge(&[changed], &mut explicit, &[twin]).is_err());
    }

    #[test]
    fn inherited_input_with_no_inherited_twin_is_refused() {
        let mut lone = user("S-1", AceType::Allow, 7);
        lone.flags = INHERITED_ACE;
        let mut explicit = vec![owner(AceType::Allow, 1)];
        assert!(merge(&[lone], &mut explicit, &[]).is_err());
        assert_eq!(explicit.len(), 1);
    }

    #[test]
    fn split_inherited_partitions() {
        let mut inh = user("S-1", AceType::Allow, 1);
        inh.flags = INHERITED_ACE;
        let (explicit, inherited) = split_inherited(&[owner(AceType::Allow, 1), inh.clone()]);
        assert_eq!(explicit.len(), 1);
        assert_eq!(inherited.len(), 1);
        assert_eq!(inherited[0].flags & INHERITED_ACE, INHERITED_ACE);
    }
}
