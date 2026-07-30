use std::env;
use std::fs;
use std::path::PathBuf;

use borsh::BorshDeserialize;
use masp_primitives::merkle_tree::CommitmentTree;
use masp_primitives::sapling::Node;
use namada_core::address;
use namada_core::hash::Hash;
use namada_core::storage::{Key, KeySeg};
use namada_sdk::migrations::{DbChanges, DbUpdateType, UpdateValue};
use namada_sdk::storage::DbColFam;
use namada_shielded_token::storage_key::{
    MASP_NOTE_COMMITMENT_ANCHOR_PREFIX, masp_commitment_anchor_key,
    masp_commitment_tree_key, masp_recovery_mode_key,
};

fn main() {
    let (tree_path, output_path) = parse_args();
    let tree = read_commitment_tree(&tree_path);
    let migration = build_migration(tree);
    let json = serde_json::to_vec_pretty(&migration)
        .expect("MASP recovery migration must serialize");

    fs::write(&output_path, &json).unwrap_or_else(|error| {
        panic!(
            "failed to write migration to {}: {error}",
            output_path.display()
        )
    });

    println!("migration: {}", output_path.display());
    println!("sha256: {}", Hash::sha256(&json));
}

fn parse_args() -> (PathBuf, PathBuf) {
    let mut args = env::args_os().skip(1);
    let tree_path = args.next().map(PathBuf::from);
    let output_path = args.next().map(PathBuf::from);

    if args.next().is_some() || tree_path.is_none() || output_path.is_none() {
        panic!(
            "usage: make-masp-recovery-migration \
             <safe-commitment-tree.borsh> <migration.json>"
        );
    }

    (
        tree_path.expect("checked above"),
        output_path.expect("checked above"),
    )
}

fn read_commitment_tree(path: &PathBuf) -> CommitmentTree<Node> {
    let bytes = fs::read(path).unwrap_or_else(|error| {
        panic!(
            "failed to read commitment tree from {}: {error}",
            path.display()
        )
    });

    CommitmentTree::try_from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "{} is not a Borsh-encoded MASP commitment tree: {error}",
            path.display()
        )
    })
}

fn build_migration(tree: CommitmentTree<Node>) -> DbChanges {
    let anchor = tree.root();
    let anchor_prefix = anchor_prefix_pattern();

    DbChanges {
        changes: vec![
            // Old roots may contain forged commitments. Remove all of them
            // before publishing the independently verified safe root.
            DbUpdateType::RepeatDelete(anchor_prefix, DbColFam::SUBSPACE),
            DbUpdateType::Add {
                key: masp_commitment_tree_key(),
                cf: DbColFam::SUBSPACE,
                value: UpdateValue::force_borsh(tree),
                force: true,
            },
            DbUpdateType::Add {
                key: masp_commitment_anchor_key(anchor),
                cf: DbColFam::SUBSPACE,
                value: UpdateValue::force_borsh(()),
                force: true,
            },
            DbUpdateType::Add {
                key: masp_recovery_mode_key(),
                cf: DbColFam::SUBSPACE,
                value: UpdateValue::force_borsh(true),
                force: true,
            },
        ],
    }
}

fn anchor_prefix_pattern() -> String {
    let prefix_key = Key::from(address::MASP.to_db_key())
        .push(&MASP_NOTE_COMMITMENT_ANCHOR_PREFIX.to_owned())
        .expect("MASP anchor prefix must be a valid storage key");

    format!("^{prefix_key}/")
}

#[cfg(test)]
mod tests {
    use super::{anchor_prefix_pattern, build_migration};
    use masp_primitives::merkle_tree::CommitmentTree;
    use masp_primitives::sapling::Node;
    use namada_sdk::migrations::DbUpdateType;

    #[test]
    fn migration_deletes_old_anchors_before_adding_safe_state() {
        let migration = build_migration(CommitmentTree::<Node>::empty());

        assert_eq!(migration.changes.len(), 4);
        assert!(matches!(
            &migration.changes[0],
            DbUpdateType::RepeatDelete(pattern, _) if pattern == &anchor_prefix_pattern()
        ));
        assert!(matches!(&migration.changes[1], DbUpdateType::Add { .. }));
        assert!(matches!(&migration.changes[2], DbUpdateType::Add { .. }));
        assert!(matches!(&migration.changes[3], DbUpdateType::Add { .. }));
    }
}
