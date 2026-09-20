// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Framing for native file-transfer messages carried by the generic relay.

use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proto::SandboxTransferFrame;

/// Maximum encoded control or data frame accepted by the transfer relay.
pub const MAX_TRANSFER_FRAME_SIZE: usize = 1024 * 1024;
/// Maximum raw tar payload in one frame, leaving room for protobuf framing.
pub const MAX_TRANSFER_DATA_SIZE: usize = 64 * 1024;

pub fn encode_frame(frame: &SandboxTransferFrame) -> std::io::Result<Vec<u8>> {
    if let Some(crate::proto::sandbox_transfer_frame::Payload::Data(data)) = &frame.payload
        && data.len() > MAX_TRANSFER_DATA_SIZE
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("transfer data exceeds {MAX_TRANSFER_DATA_SIZE} byte limit"),
        ));
    }
    let payload = frame.encode_to_vec();
    if payload.len() > MAX_TRANSFER_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("transfer frame exceeds {MAX_TRANSFER_FRAME_SIZE} byte limit"),
        ));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| std::io::Error::other("transfer frame length exceeds u32"))?;
    let mut encoded = Vec::with_capacity(4 + payload.len());
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(&payload);
    Ok(encoded)
}

pub async fn write_frame<W>(writer: &mut W, frame: &SandboxTransferFrame) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&encode_frame(frame)?).await
}

pub async fn read_frame<R>(reader: &mut R) -> std::io::Result<Option<SandboxTransferFrame>>
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
    if length > MAX_TRANSFER_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("transfer frame exceeds {MAX_TRANSFER_FRAME_SIZE} byte limit"),
        ));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    let frame = SandboxTransferFrame::decode(payload.as_slice())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    encode_frame(&frame)?;
    Ok(Some(frame))
}

#[derive(Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
}

impl FrameDecoder {
    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn next_frame(&mut self) -> std::io::Result<Option<SandboxTransferFrame>> {
        if self.buffer.len() < 4 {
            return Ok(None);
        }
        let length =
            u32::from_be_bytes(self.buffer[..4].try_into().expect("four-byte prefix")) as usize;
        if length > MAX_TRANSFER_FRAME_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("transfer frame exceeds {MAX_TRANSFER_FRAME_SIZE} byte limit"),
            ));
        }
        if self.buffer.len() < 4 + length {
            return Ok(None);
        }
        let frame = SandboxTransferFrame::decode(&self.buffer[4..4 + length])
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        encode_frame(&frame)?;
        self.buffer.drain(..4 + length);
        Ok(Some(frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::sandbox_transfer_frame;

    #[test]
    fn decoder_handles_fragmented_frames_and_enforces_data_limit() {
        let frame = SandboxTransferFrame {
            payload: Some(sandbox_transfer_frame::Payload::Data(b"archive".to_vec())),
        };
        let encoded = encode_frame(&frame).unwrap();
        let mut decoder = FrameDecoder::default();
        decoder.push(&encoded[..2]);
        assert!(decoder.next_frame().unwrap().is_none());
        decoder.push(&encoded[2..]);
        assert_eq!(decoder.next_frame().unwrap(), Some(frame));

        let oversized = SandboxTransferFrame {
            payload: Some(sandbox_transfer_frame::Payload::Data(vec![
                0;
                MAX_TRANSFER_DATA_SIZE
                    + 1
            ])),
        };
        assert_eq!(
            encode_frame(&oversized).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }
}
