use {
    solana_clock::Slot,
    solana_pubkey::Pubkey,
    solana_signature::{Signature, SIGNATURE_BYTES},
    thiserror::Error,
};

pub const MCP_CONTROL_MSG_RELAY_ATTESTATION: u8 = 0x01;
pub const RELAY_ATTESTATION_VERSION_V1: u8 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayAttestationEntry {
    pub proposer_index: u32,
    pub commitment: [u8; 32],
    pub proposer_signature: Signature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayAttestationV1 {
    pub slot: Slot,
    pub relay_index: u32,
    pub entries: Vec<RelayAttestationEntry>,
    pub relay_signature: Signature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayAttestationDispatch {
    pub slot: Slot,
    pub leader_pubkey: Pubkey,
    pub frame: Vec<u8>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RelaySubmitError {
    #[error("relay attestation payload is too short")]
    PayloadTooShort,
    #[error("invalid relay attestation version: {0}")]
    InvalidVersion(u8),
    #[error("relay attestation payload has trailing bytes")]
    TrailingBytes,
    #[error("relay attestation entries must be sorted and unique by proposer_index")]
    UnsortedOrDuplicateEntries,
    #[error("unknown MCP control message type: {0:#x}")]
    UnknownMessageType(u8),
    #[error("missing leader for slot {0}")]
    MissingLeader(Slot),
}

impl RelayAttestationV1 {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + 8 + 4 + 1 + self.entries.len() * (4 + 32 + 64));
        bytes.push(RELAY_ATTESTATION_VERSION_V1);
        bytes.extend_from_slice(&self.slot.to_le_bytes());
        bytes.extend_from_slice(&self.relay_index.to_le_bytes());
        bytes.push(self.entries.len() as u8);
        for entry in &self.entries {
            bytes.extend_from_slice(&entry.proposer_index.to_le_bytes());
            bytes.extend_from_slice(&entry.commitment);
            bytes.extend_from_slice(entry.proposer_signature.as_ref());
        }
        bytes
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.signing_bytes();
        bytes.extend_from_slice(self.relay_signature.as_ref());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RelaySubmitError> {
        if bytes.len() < 1 + 8 + 4 + 1 + SIGNATURE_BYTES {
            return Err(RelaySubmitError::PayloadTooShort);
        }

        let mut offset = 0usize;
        let version = bytes[offset];
        offset += 1;
        if version != RELAY_ATTESTATION_VERSION_V1 {
            return Err(RelaySubmitError::InvalidVersion(version));
        }

        let slot = Slot::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let relay_index = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let entries_len = bytes[offset] as usize;
        offset += 1;

        let mut entries = Vec::with_capacity(entries_len);
        let mut prev_index = None;
        for _ in 0..entries_len {
            if bytes.len() < offset + 4 + 32 + SIGNATURE_BYTES {
                return Err(RelaySubmitError::PayloadTooShort);
            }
            let proposer_index = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            offset += 4;
            if prev_index.is_some_and(|prev| proposer_index <= prev) {
                return Err(RelaySubmitError::UnsortedOrDuplicateEntries);
            }
            prev_index = Some(proposer_index);

            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(&bytes[offset..offset + 32]);
            offset += 32;
            let proposer_signature =
                Signature::from(<[u8; 64]>::try_from(&bytes[offset..offset + 64]).unwrap());
            offset += 64;

            entries.push(RelayAttestationEntry {
                proposer_index,
                commitment,
                proposer_signature,
            });
        }

        if bytes.len() < offset + SIGNATURE_BYTES {
            return Err(RelaySubmitError::PayloadTooShort);
        }
        let relay_signature =
            Signature::from(<[u8; 64]>::try_from(&bytes[offset..offset + 64]).unwrap());
        offset += 64;

        if offset != bytes.len() {
            return Err(RelaySubmitError::TrailingBytes);
        }

        Ok(Self {
            slot,
            relay_index,
            entries,
            relay_signature,
        })
    }

    pub fn verify_relay_signature(&self, relay_pubkey: &Pubkey) -> bool {
        self.relay_signature
            .verify(relay_pubkey.as_ref(), &self.signing_bytes())
    }

    pub fn valid_entries<F>(&self, mut proposer_pubkey_for_index: F) -> Vec<RelayAttestationEntry>
    where
        F: FnMut(u32) -> Option<Pubkey>,
    {
        self.entries
            .iter()
            .filter(|entry| {
                proposer_pubkey_for_index(entry.proposer_index).is_some_and(|pubkey| {
                    entry
                        .proposer_signature
                        .verify(pubkey.as_ref(), &entry.commitment)
                })
            })
            .cloned()
            .collect()
    }
}

pub fn encode_relay_attestation_frame(attestation_bytes: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + attestation_bytes.len());
    frame.push(MCP_CONTROL_MSG_RELAY_ATTESTATION);
    frame.extend_from_slice(attestation_bytes);
    frame
}

pub fn decode_relay_attestation_frame(frame: &[u8]) -> Result<&[u8], RelaySubmitError> {
    if frame.is_empty() {
        return Err(RelaySubmitError::PayloadTooShort);
    }
    if frame[0] != MCP_CONTROL_MSG_RELAY_ATTESTATION {
        return Err(RelaySubmitError::UnknownMessageType(frame[0]));
    }
    Ok(&frame[1..])
}

pub fn build_relay_attestation_dispatch<F>(
    attestation: &RelayAttestationV1,
    mut leader_for_slot: F,
) -> Result<RelayAttestationDispatch, RelaySubmitError>
where
    F: FnMut(Slot) -> Option<Pubkey>,
{
    let leader_pubkey = leader_for_slot(attestation.slot)
        .ok_or(RelaySubmitError::MissingLeader(attestation.slot))?;
    Ok(RelayAttestationDispatch {
        slot: attestation.slot,
        leader_pubkey,
        frame: encode_relay_attestation_frame(&attestation.to_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use {super::*, solana_keypair::Keypair, solana_signer::Signer, std::collections::HashMap};

    fn signed_entry(
        proposer_index: u32,
        commitment: [u8; 32],
        proposer: &Keypair,
    ) -> RelayAttestationEntry {
        RelayAttestationEntry {
            proposer_index,
            commitment,
            proposer_signature: proposer.sign_message(&commitment),
        }
    }

    fn signed_attestation(
        slot: Slot,
        relay_index: u32,
        entries: Vec<RelayAttestationEntry>,
        relay: &Keypair,
    ) -> RelayAttestationV1 {
        let mut attestation = RelayAttestationV1 {
            slot,
            relay_index,
            entries,
            relay_signature: Signature::default(),
        };
        let signature = relay.sign_message(&attestation.signing_bytes());
        attestation.relay_signature = signature;
        attestation
    }

    #[test]
    fn test_attestation_roundtrip_and_signature_checks() {
        let relay = Keypair::new();
        let proposer_a = Keypair::new();
        let proposer_b = Keypair::new();
        let commitment_a = [11u8; 32];
        let commitment_b = [22u8; 32];
        let attestation = signed_attestation(
            77,
            9,
            vec![
                signed_entry(3, commitment_a, &proposer_a),
                signed_entry(8, commitment_b, &proposer_b),
            ],
            &relay,
        );

        let bytes = attestation.to_bytes();
        let decoded = RelayAttestationV1::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, attestation);
        assert!(decoded.verify_relay_signature(&relay.pubkey()));

        let proposer_map =
            HashMap::from([(3u32, proposer_a.pubkey()), (8u32, proposer_b.pubkey())]);
        let valid_entries = decoded.valid_entries(|index| proposer_map.get(&index).copied());
        assert_eq!(valid_entries.len(), 2);
        assert_eq!(valid_entries[0].proposer_index, 3);
        assert_eq!(valid_entries[1].proposer_index, 8);
    }

    #[test]
    fn test_unsorted_entries_rejected() {
        let relay = Keypair::new();
        let proposer_a = Keypair::new();
        let proposer_b = Keypair::new();
        let attestation = signed_attestation(
            1,
            2,
            vec![
                signed_entry(9, [1u8; 32], &proposer_a),
                signed_entry(4, [2u8; 32], &proposer_b),
            ],
            &relay,
        );

        let err = RelayAttestationV1::from_bytes(&attestation.to_bytes()).unwrap_err();
        assert_eq!(err, RelaySubmitError::UnsortedOrDuplicateEntries);
    }

    #[test]
    fn test_dispatch_frame_roundtrip() {
        let relay = Keypair::new();
        let proposer = Keypair::new();
        let attestation =
            signed_attestation(55, 12, vec![signed_entry(1, [5u8; 32], &proposer)], &relay);
        let leader = Pubkey::new_unique();

        let dispatch = build_relay_attestation_dispatch(&attestation, |slot| {
            if slot == 55 {
                Some(leader)
            } else {
                None
            }
        })
        .unwrap();

        assert_eq!(dispatch.slot, 55);
        assert_eq!(dispatch.leader_pubkey, leader);
        let payload = decode_relay_attestation_frame(&dispatch.frame).unwrap();
        let decoded = RelayAttestationV1::from_bytes(payload).unwrap();
        assert_eq!(decoded, attestation);
    }

    #[test]
    fn test_unknown_frame_type_rejected() {
        let err = decode_relay_attestation_frame(&[0x02, 0x00]).unwrap_err();
        assert_eq!(err, RelaySubmitError::UnknownMessageType(0x02));
    }
}
