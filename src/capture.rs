//! Completeness of one producer's saved observation prefix.
use hibana::runtime::tap::TapEvent;

/// An unfiltered observation prefix checked against its producer's saved
/// `TapPort::checkpoint()`. Different producers need separate captures.
///
/// This borrows the records without allocating or retaining a runtime cursor.
/// The checkpoint must be saved independently from the same producer; deriving
/// it from the supplied record count would conceal a missing suffix. Checking
/// completeness does not authenticate records, establish protocol eligibility
/// or prove that a session or application effect completed.
#[derive(Clone, Copy, Debug)]
pub struct Capture<'a> {
    records: &'a [TapEvent],
}

/// A capture cannot account for its producer's complete observation prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureError {
    /// The public producer counter has no unambiguous next ordinal.
    CounterExhausted,
    /// Saved record count differs from the independently recorded checkpoint.
    Length { expected: u32, actual: usize },
    /// This record does not have its required zero-based ordinal.
    Ordinal { index: usize, actual: u32 },
}

impl<'a> Capture<'a> {
    /// Check an unfiltered capture and its independently saved end checkpoint.
    ///
    /// Missing prefixes, suffixes, overwritten records, duplicates, reordered
    /// records and exhausted ordinals are errors. An empty prefix at checkpoint
    /// zero is valid; it is not evidence that any protocol operation occurred.
    pub fn new(records: &'a [TapEvent], checkpoint: Option<u32>) -> Result<Self, CaptureError> {
        let end = checkpoint
            .filter(|&ordinal| ordinal != u32::MAX)
            .ok_or(CaptureError::CounterExhausted)?;
        if usize::try_from(end).ok() != Some(records.len()) {
            return Err(CaptureError::Length {
                expected: end,
                actual: records.len(),
            });
        }
        for (index, record) in records.iter().enumerate() {
            if record.ts() != index as u32 {
                return Err(CaptureError::Ordinal {
                    index,
                    actual: record.ts(),
                });
            }
        }
        Ok(Self { records })
    }

    /// The unchanged complete observation prefix.
    pub const fn records(&self) -> &'a [TapEvent] {
        self.records
    }
}
