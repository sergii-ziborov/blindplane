//! Parallel batch sealing.

use blindplane_crypto::aead::Suite;
use blindplane_wire::{BlindIndex, RecordContext, SealedRecord};

use crate::error::CryptoError;
use crate::identity::{Author, Recipient};
use crate::sealing::seal;

/// An owned work item for parallel sealing.
pub struct BatchItem {
    /// Authenticated routing context.
    pub context: RecordContext,
    /// Plaintext, retained only by the caller and the worker thread.
    pub plaintext: Vec<u8>,
    /// Independent recipients.
    pub recipients: Vec<Recipient>,
    /// Optional exact-search indexes.
    pub indexes: Vec<BlindIndex>,
}

/// Seal independent records across all available cores, preserving input order.
///
/// Sealing is embarrassingly parallel: each record has its own object secret,
/// so there is nothing to synchronize beyond collecting the results.
pub fn seal_batch(
    author: &Author,
    items: &[BatchItem],
    suite: Suite,
) -> Vec<Result<SealedRecord, CryptoError>> {
    let workers = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(items.len().max(1));

    if workers <= 1 || items.len() <= 1 {
        return items
            .iter()
            .map(|item| {
                seal(
                    author,
                    item.context.clone(),
                    &item.plaintext,
                    &item.recipients,
                    item.indexes.clone(),
                    suite,
                )
            })
            .collect();
    }

    let mut results: Vec<Option<Result<SealedRecord, CryptoError>>> =
        (0..items.len()).map(|_| None).collect();

    std::thread::scope(|scope| {
        let chunk_size = items.len().div_ceil(workers);
        let mut handles = Vec::with_capacity(workers);
        for (chunk_index, chunk) in items.chunks(chunk_size).enumerate() {
            handles.push((
                chunk_index * chunk_size,
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|item| {
                            seal(
                                author,
                                item.context.clone(),
                                &item.plaintext,
                                &item.recipients,
                                item.indexes.clone(),
                                suite,
                            )
                        })
                        .collect::<Vec<_>>()
                }),
            ));
        }
        for (offset, handle) in handles {
            let chunk_results = handle.join().expect("sealing worker panicked");
            for (i, result) in chunk_results.into_iter().enumerate() {
                results[offset + i] = Some(result);
            }
        }
    });

    results
        .into_iter()
        .map(|slot| slot.expect("every index is filled by exactly one worker"))
        .collect()
}
