// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Framing for native exec messages carried by the generic relay byte stream.

use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proto::ExecRelayFrame;

/// Maximum encoded exec frame accepted from either side of a relay.
pub const MAX_EXEC_RELAY_FRAME_SIZE: usize = 1024 * 1024;

/// Encode one frame with a four-byte network-order length prefix.
pub fn encode_frame(frame: &ExecRelayFrame) -> std::io::Result<Vec<u8>> {
    let payload = frame.encode_to_vec();
    let length = u32::try_from(payload.len())
        .map_err(|_| std::io::Error::other("exec relay frame length exceeds u32"))?;
    let mut encoded = Vec::with_capacity(4 + payload.len());
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(&payload);
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{ExecRelayExit, exec_relay_frame};

    #[test]
    fn decoder_handles_fragmented_and_coalesced_frames() {
        let first = ExecRelayFrame {
            payload: Some(exec_relay_frame::Payload::Stdout(b"hello".to_vec())),
        };
        let second = ExecRelayFrame {
            payload: Some(exec_relay_frame::Payload::Exit(ExecRelayExit {
                exit_code: 7,
            })),
        };
        let mut encoded = encode_frame(&first).unwrap();
        encoded.extend(encode_frame(&second).unwrap());

        let split = 3;
        let mut decoder = FrameDecoder::default();
        decoder.push(&encoded[..split]);
        assert!(decoder.next_frame().unwrap().is_none());
        decoder.push(&encoded[split..]);
        assert_eq!(decoder.next_frame().unwrap(), Some(first));
        assert_eq!(decoder.next_frame().unwrap(), Some(second));
        assert!(decoder.next_frame().unwrap().is_none());
    }

    #[test]
    fn decoder_rejects_oversized_frame_before_buffering_payload() {
        let mut decoder = FrameDecoder::default();
        decoder.push(
            &u32::try_from(MAX_EXEC_RELAY_FRAME_SIZE + 1)
                .unwrap()
                .to_be_bytes(),
        );
        let error = decoder.next_frame().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}

/// Write one framed native-exec message.
pub async fn write_frame<W>(writer: &mut W, frame: &ExecRelayFrame) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let encoded = encode_frame(frame)?;
    writer.write_all(&encoded).await
}

/// Read one framed native-exec message. EOF before a header returns `None`.
pub async fn read_frame<R>(reader: &mut R) -> std::io::Result<Option<ExecRelayFrame>>
where
    R: AsyncRead + Unpin,
{
    let mut length = [0_u8; 4];
    match reader.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_EXEC_RELAY_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("exec relay frame exceeds {MAX_EXEC_RELAY_FRAME_SIZE} byte limit"),
        ));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    ExecRelayFrame::decode(payload.as_slice())
        .map(Some)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

/// Incremental decoder for relay chunks whose boundaries do not match frames.
#[derive(Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
}

impl FrameDecoder {
    /// Append one arbitrary relay chunk.
    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Decode the next complete frame, if one is buffered.
    pub fn next_frame(&mut self) -> std::io::Result<Option<ExecRelayFrame>> {
        if self.buffer.len() < 4 {
            return Ok(None);
        }
        let length =
            u32::from_be_bytes(self.buffer[..4].try_into().expect("four-byte prefix")) as usize;
        if length > MAX_EXEC_RELAY_FRAME_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("exec relay frame exceeds {MAX_EXEC_RELAY_FRAME_SIZE} byte limit"),
            ));
        }
        if self.buffer.len() < 4 + length {
            return Ok(None);
        }
        let frame = ExecRelayFrame::decode(&self.buffer[4..4 + length])
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        self.buffer.drain(..4 + length);
        Ok(Some(frame))
    }
}
