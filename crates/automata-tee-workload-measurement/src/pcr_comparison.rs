use alloy::{
    primitives::{B256, Bytes, FixedBytes},
    sol,
    sol_types::{SolType, SolValue, abi::TokenSeq},
};
use anyhow::{Context, Result, bail, ensure};

pub const STATIC: u16 = 0;
pub const DYNAMIC_SUBSET: u16 = 1;
pub const DYNAMIC_SUBSEQUENCE: u16 = 2;
pub const DYNAMIC_INDEXED_EVENT_SETS: u16 = 3;
pub const EXTEND_FROM_ZERO: u16 = 4;

sol! {
    #[derive(PartialEq, Eq)]
    struct ComparisonBytes48 {
        bytes32 first;
        bytes16 second;
    }

    struct EncodedIndexedEventSet256 {
        uint16 eventIndex;
        bytes32[] allowedValues;
    }

    struct EncodedIndexedEventSets256 {
        uint16 expectedEventCount;
        EncodedIndexedEventSet256[] checkedEvents;
    }

    struct EncodedIndexedEventSet384 {
        uint16 eventIndex;
        ComparisonBytes48[] allowedValues;
    }

    struct EncodedIndexedEventSets384 {
        uint16 expectedEventCount;
        EncodedIndexedEventSet384[] checkedEvents;
    }
}

type StaticComparison256 = sol!((uint16, bytes32));
type StaticComparison384 = sol!((uint16, ComparisonBytes48));
type DynamicComparison256 = sol!((uint16, bytes32[]));
type DynamicComparison384 = sol!((uint16, ComparisonBytes48[]));
type IndexedEventSetsComparison256 = sol!((uint16, EncodedIndexedEventSets256));
type IndexedEventSetsComparison384 = sol!((uint16, EncodedIndexedEventSets384));
type ExtendFromZeroComparison256 = sol!((uint16, bytes32));
type ExtendFromZeroComparison384 = sol!((uint16, ComparisonBytes48));

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedEventSet256 {
    pub event_index: u16,
    pub allowed_values: Vec<B256>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedEventSets256 {
    pub expected_event_count: u16,
    pub checked_events: Vec<IndexedEventSet256>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedEventSet384 {
    pub event_index: u16,
    pub allowed_values: Vec<[u8; 48]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedEventSets384 {
    pub expected_event_count: u16,
    pub checked_events: Vec<IndexedEventSet384>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PcrComparison256 {
    Static(B256),
    DynamicSubset(Vec<B256>),
    DynamicSubsequence(Vec<B256>),
    DynamicIndexedEventSets(IndexedEventSets256),
    ExtendFromZero(B256),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PcrComparison384 {
    Static([u8; 48]),
    DynamicSubset(Vec<[u8; 48]>),
    DynamicSubsequence(Vec<[u8; 48]>),
    DynamicIndexedEventSets(IndexedEventSets384),
    ExtendFromZero([u8; 48]),
}

pub fn comparison_type(comparison: &[u8]) -> Result<u16> {
    ensure!(
        comparison.len() >= 32,
        "PCR comparison is shorter than one ABI word"
    );
    ensure!(
        comparison[..30].iter().all(|byte| *byte == 0),
        "PCR comparison type does not fit uint16"
    );
    Ok(u16::from_be_bytes([comparison[30], comparison[31]]))
}

pub fn encode_static256(expected_value: B256) -> Bytes {
    (STATIC, expected_value).abi_encode_params().into()
}

pub fn encode_static384(expected_value: [u8; 48]) -> Bytes {
    (STATIC, encode_bytes48(expected_value))
        .abi_encode_params()
        .into()
}

pub fn encode_dynamic256(comparison_type: u16, landmarks: Vec<B256>) -> Result<Bytes> {
    ensure_dynamic_landmark_type(comparison_type)?;
    Ok((comparison_type, landmarks).abi_encode_params().into())
}

pub fn encode_dynamic384(comparison_type: u16, landmarks: Vec<[u8; 48]>) -> Result<Bytes> {
    ensure_dynamic_landmark_type(comparison_type)?;
    let landmarks = landmarks
        .into_iter()
        .map(encode_bytes48)
        .collect::<Vec<_>>();
    Ok((comparison_type, landmarks).abi_encode_params().into())
}

pub fn encode_indexed_event_sets256(rule: IndexedEventSets256) -> Bytes {
    let encoded = EncodedIndexedEventSets256 {
        expectedEventCount: rule.expected_event_count,
        checkedEvents: rule
            .checked_events
            .into_iter()
            .map(|checked| EncodedIndexedEventSet256 {
                eventIndex: checked.event_index,
                allowedValues: checked.allowed_values,
            })
            .collect(),
    };
    (DYNAMIC_INDEXED_EVENT_SETS, encoded)
        .abi_encode_params()
        .into()
}

pub fn encode_indexed_event_sets384(rule: IndexedEventSets384) -> Bytes {
    let encoded = EncodedIndexedEventSets384 {
        expectedEventCount: rule.expected_event_count,
        checkedEvents: rule
            .checked_events
            .into_iter()
            .map(|checked| EncodedIndexedEventSet384 {
                eventIndex: checked.event_index,
                allowedValues: checked
                    .allowed_values
                    .into_iter()
                    .map(encode_bytes48)
                    .collect(),
            })
            .collect(),
    };
    (DYNAMIC_INDEXED_EVENT_SETS, encoded)
        .abi_encode_params()
        .into()
}

pub fn encode_extend_from_zero256(extend_value: B256) -> Bytes {
    (EXTEND_FROM_ZERO, extend_value).abi_encode_params().into()
}

pub fn encode_extend_from_zero384(extend_value: [u8; 48]) -> Bytes {
    (EXTEND_FROM_ZERO, encode_bytes48(extend_value))
        .abi_encode_params()
        .into()
}

pub fn decode256(comparison: &[u8]) -> Result<PcrComparison256> {
    match comparison_type(comparison)? {
        STATIC => {
            let decoded = StaticComparison256::abi_decode_params_validate(comparison)
                .context("decode STATIC SHA-256 PCR comparison")?;
            require_canonical::<StaticComparison256>(comparison, &decoded)?;
            Ok(PcrComparison256::Static(decoded.1))
        }
        DYNAMIC_SUBSET | DYNAMIC_SUBSEQUENCE => {
            let decoded = DynamicComparison256::abi_decode_params_validate(comparison)
                .context("decode dynamic SHA-256 PCR comparison")?;
            require_canonical::<DynamicComparison256>(comparison, &decoded)?;
            if decoded.0 == DYNAMIC_SUBSET {
                Ok(PcrComparison256::DynamicSubset(decoded.1))
            } else {
                Ok(PcrComparison256::DynamicSubsequence(decoded.1))
            }
        }
        DYNAMIC_INDEXED_EVENT_SETS => {
            let decoded = IndexedEventSetsComparison256::abi_decode_params_validate(comparison)
                .context("decode indexed SHA-256 PCR comparison")?;
            require_canonical::<IndexedEventSetsComparison256>(comparison, &decoded)?;
            Ok(PcrComparison256::DynamicIndexedEventSets(
                IndexedEventSets256 {
                    expected_event_count: decoded.1.expectedEventCount,
                    checked_events: decoded
                        .1
                        .checkedEvents
                        .into_iter()
                        .map(|checked| IndexedEventSet256 {
                            event_index: checked.eventIndex,
                            allowed_values: checked.allowedValues,
                        })
                        .collect(),
                },
            ))
        }
        EXTEND_FROM_ZERO => {
            let decoded = ExtendFromZeroComparison256::abi_decode_params_validate(comparison)
                .context("decode EXTEND_FROM_ZERO SHA-256 PCR comparison")?;
            require_canonical::<ExtendFromZeroComparison256>(comparison, &decoded)?;
            Ok(PcrComparison256::ExtendFromZero(decoded.1))
        }
        comparison_type => bail!("unsupported SHA-256 PCR comparison type {comparison_type}"),
    }
}

pub fn decode384(comparison: &[u8]) -> Result<PcrComparison384> {
    match comparison_type(comparison)? {
        STATIC => {
            let decoded = StaticComparison384::abi_decode_params_validate(comparison)
                .context("decode STATIC SHA-384 PCR comparison")?;
            require_canonical::<StaticComparison384>(comparison, &decoded)?;
            Ok(PcrComparison384::Static(decode_bytes48(&decoded.1)))
        }
        DYNAMIC_SUBSET | DYNAMIC_SUBSEQUENCE => {
            let decoded = DynamicComparison384::abi_decode_params_validate(comparison)
                .context("decode dynamic SHA-384 PCR comparison")?;
            require_canonical::<DynamicComparison384>(comparison, &decoded)?;
            let landmarks = decoded.1.iter().map(decode_bytes48).collect();
            if decoded.0 == DYNAMIC_SUBSET {
                Ok(PcrComparison384::DynamicSubset(landmarks))
            } else {
                Ok(PcrComparison384::DynamicSubsequence(landmarks))
            }
        }
        DYNAMIC_INDEXED_EVENT_SETS => {
            let decoded = IndexedEventSetsComparison384::abi_decode_params_validate(comparison)
                .context("decode indexed SHA-384 PCR comparison")?;
            require_canonical::<IndexedEventSetsComparison384>(comparison, &decoded)?;
            Ok(PcrComparison384::DynamicIndexedEventSets(
                IndexedEventSets384 {
                    expected_event_count: decoded.1.expectedEventCount,
                    checked_events: decoded
                        .1
                        .checkedEvents
                        .into_iter()
                        .map(|checked| IndexedEventSet384 {
                            event_index: checked.eventIndex,
                            allowed_values: checked
                                .allowedValues
                                .iter()
                                .map(decode_bytes48)
                                .collect(),
                        })
                        .collect(),
                },
            ))
        }
        EXTEND_FROM_ZERO => {
            let decoded = ExtendFromZeroComparison384::abi_decode_params_validate(comparison)
                .context("decode EXTEND_FROM_ZERO SHA-384 PCR comparison")?;
            require_canonical::<ExtendFromZeroComparison384>(comparison, &decoded)?;
            Ok(PcrComparison384::ExtendFromZero(decode_bytes48(&decoded.1)))
        }
        comparison_type => bail!("unsupported SHA-384 PCR comparison type {comparison_type}"),
    }
}

fn ensure_dynamic_landmark_type(comparison_type: u16) -> Result<()> {
    ensure!(
        matches!(comparison_type, DYNAMIC_SUBSET | DYNAMIC_SUBSEQUENCE),
        "comparison type {comparison_type} does not use a landmark array"
    );
    Ok(())
}

fn require_canonical<T>(comparison: &[u8], decoded: &T::RustType) -> Result<()>
where
    T: SolType,
    for<'a> T::Token<'a>: TokenSeq<'a>,
{
    ensure!(
        T::abi_encode_params(decoded) == comparison,
        "PCR comparison is not canonically ABI encoded"
    );
    Ok(())
}

fn encode_bytes48(value: [u8; 48]) -> ComparisonBytes48 {
    ComparisonBytes48 {
        first: B256::from_slice(&value[..32]),
        second: FixedBytes::<16>::from_slice(&value[32..]),
    }
}

fn decode_bytes48(value: &ComparisonBytes48) -> [u8; 48] {
    let mut decoded = [0u8; 48];
    decoded[..32].copy_from_slice(value.first.as_slice());
    decoded[32..].copy_from_slice(value.second.as_slice());
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_encoding_matches_solidity_abi_encode_layout() {
        let first = B256::with_last_byte(0x11);
        let second = B256::with_last_byte(0x22);
        let encoded = encode_dynamic256(DYNAMIC_SUBSEQUENCE, vec![first, second]).unwrap();

        assert_eq!(encoded.len(), 5 * 32);
        assert_eq!(comparison_type(&encoded).unwrap(), DYNAMIC_SUBSEQUENCE);
        assert_eq!(encoded[63], 64);
        assert_eq!(encoded[95], 2);
        assert_eq!(&encoded[96..128], first.as_slice());
        assert_eq!(&encoded[128..160], second.as_slice());
        assert_eq!(
            decode256(&encoded).unwrap(),
            PcrComparison256::DynamicSubsequence(vec![first, second])
        );
    }

    #[test]
    fn indexed_encoding_round_trips_skipped_indexes() {
        let rule = IndexedEventSets256 {
            expected_event_count: 4,
            checked_events: vec![
                IndexedEventSet256 {
                    event_index: 0,
                    allowed_values: vec![B256::with_last_byte(0x10)],
                },
                IndexedEventSet256 {
                    event_index: 3,
                    allowed_values: vec![B256::with_last_byte(0x40)],
                },
            ],
        };
        let encoded = encode_indexed_event_sets256(rule.clone());
        assert_eq!(
            decode256(&encoded).unwrap(),
            PcrComparison256::DynamicIndexedEventSets(rule)
        );
    }

    #[test]
    fn decoder_rejects_trailing_data() {
        let mut encoded = encode_static256(B256::with_last_byte(0x11)).to_vec();
        encoded.extend_from_slice(&[0u8; 32]);
        assert!(
            decode256(&encoded)
                .unwrap_err()
                .to_string()
                .contains("canonically")
        );
    }

    #[test]
    fn extend_from_zero_encodings_round_trip_at_exact_bank_width() {
        let extend256 = B256::repeat_byte(0x25);
        let encoded256 = encode_extend_from_zero256(extend256);
        assert_eq!(encoded256.len(), 64);
        assert_eq!(
            decode256(&encoded256).unwrap(),
            PcrComparison256::ExtendFromZero(extend256)
        );

        let extend384 = [0x38; 48];
        let encoded384 = encode_extend_from_zero384(extend384);
        assert_eq!(encoded384.len(), 96);
        assert_eq!(
            decode384(&encoded384).unwrap(),
            PcrComparison384::ExtendFromZero(extend384)
        );
    }
}
