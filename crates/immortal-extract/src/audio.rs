// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

//! Wwise audio package (`.pck`), SoundBank (`BKHD`), `.wem` stream parser,
//! and standard RIFF `.wav` exporter.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Seek, SeekFrom, Write};

use crate::error::ExtractError;

/// Wwise Package magic `0x41 0x4B 0x50 0x4B` (`"AKPK"`).
pub const AKPK_MAGIC: u32 = 0x4B504B41;

/// Wwise SoundBank chunk magic `0x42 0x4B 0x48 0x44` (`"BKHD"`).
pub const BKHD_MAGIC: u32 = 0x44484B42;

/// Standard RIFF magic `"RIFF"`.
pub const RIFF_MAGIC: u32 = 0x46464952;

/// Standard WAVE format identifier `"WAVE"`.
pub const WAVE_MAGIC: u32 = 0x45564157;

/// Standard fmt chunk identifier `"fmt "`.
pub const FMT_MAGIC: u32 = 0x20746D66;

/// Standard data chunk identifier `"data"`.
pub const DATA_MAGIC: u32 = 0x61746164;

/// Audio format tags for RIFF WAVE.
pub const WAVE_FORMAT_PCM: u16 = 0x0001;
pub const WAVE_FORMAT_MS_ADPCM: u16 = 0x0002;
pub const WAVE_FORMAT_IMA_ADPCM: u16 = 0x0011;
pub const WAVE_FORMAT_WWISE_VORBIS: u16 = 0xFFFF;

/// Describes an audio or soundbank file entry inside an AKPK archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PckEntry {
    /// Numeric file ID (e.g. 12345678).
    pub id: u32,
    /// Block alignment (typically 1 or 2048).
    pub block_size: u32,
    /// Exact file payload size in bytes.
    pub file_size: u32,
    /// Absolute byte offset in the `.pck` file.
    pub file_offset: u64,
    /// Language code ID (0 = SFX / language agnostic).
    pub language_id: u32,
    /// True if entry is an embedded SoundBank (`.bnk`), false if stream (`.wem`).
    pub is_soundbank: bool,
}

/// Parsed Wwise AKPK audio package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PckArchive {
    pub header_size: u32,
    pub version: u32,
    pub soundbanks: Vec<PckEntry>,
    pub streams: Vec<PckEntry>,
}

impl PckArchive {
    /// Reads and parses an AKPK package header and file tables.
    pub fn read<R: Read + Seek>(reader: &mut R) -> Result<Self, ExtractError> {
        let magic = reader.read_u32::<LittleEndian>()?;
        if magic != AKPK_MAGIC {
            return Err(ExtractError::InvalidMagic {
                expected: AKPK_MAGIC,
                found: magic,
            });
        }

        let header_size = reader.read_u32::<LittleEndian>()?;
        let version = reader.read_u32::<LittleEndian>()?;

        // Detect if archive uses standard Wwise multi-table header (lang, bank, stream, ext sizes)
        // Check if sum of table sizes + 28 bytes equals header_size + 8
        let pos_before_tables = reader.stream_position()?;
        let first_val = reader.read_u32::<LittleEndian>()?;

        let is_wwise_multi_table = if let (Ok(bank_sz), Ok(stream_sz), Ok(ext_sz)) = (
            reader.read_u32::<LittleEndian>(),
            reader.read_u32::<LittleEndian>(),
            reader.read_u32::<LittleEndian>(),
        ) {
            let total = 28u64 + (first_val as u64) + (bank_sz as u64) + (stream_sz as u64) + (ext_sz as u64);
            total == (header_size as u64 + 8)
        } else {
            false
        };

        if is_wwise_multi_table {
            // first_val is lang_table_size. Skip language table.
            if first_val > 0 {
                let mut lang_buf = vec![0u8; first_val as usize];
                reader.read_exact(&mut lang_buf)?;
            }
        } else {
            // Legacy / synthetic format: restore position after version
            reader.seek(SeekFrom::Start(pos_before_tables))?;
            let lang_table_size = reader.read_u32::<LittleEndian>()?;
            let mut lang_bytes_read = 0;
            while lang_bytes_read < lang_table_size {
                let _offset = reader.read_u32::<LittleEndian>()?;
                let _id = reader.read_u32::<LittleEndian>()?;
                lang_bytes_read += 8;
            }
        }

        // SoundBanks table
        let bank_count = reader.read_u32::<LittleEndian>()?;
        let mut soundbanks = Vec::with_capacity(bank_count as usize);
        for _ in 0..bank_count {
            let id = reader.read_u32::<LittleEndian>()?;
            let block_size = reader.read_u32::<LittleEndian>()?;
            let file_size = reader.read_u32::<LittleEndian>()?;
            let file_offset_raw = reader.read_u32::<LittleEndian>()?;
            let language_id = reader.read_u32::<LittleEndian>()?;

            let file_offset = if block_size > 1
                && (file_offset_raw < (header_size / block_size.max(1))
                    || ((file_offset_raw as u64) < 100_000 && header_size > 100_000))
            {
                (file_offset_raw as u64) * (block_size as u64)
            } else {
                file_offset_raw as u64
            };

            soundbanks.push(PckEntry {
                id,
                block_size,
                file_size,
                file_offset,
                language_id,
                is_soundbank: true,
            });
        }

        // Stream table (.wem files)
        let stream_count = reader.read_u32::<LittleEndian>()?;
        let mut streams = Vec::with_capacity(stream_count as usize);
        for _ in 0..stream_count {
            let id = reader.read_u32::<LittleEndian>()?;
            let block_size = reader.read_u32::<LittleEndian>()?;
            let file_size = reader.read_u32::<LittleEndian>()?;
            let file_offset_raw = reader.read_u32::<LittleEndian>()?;
            let language_id = reader.read_u32::<LittleEndian>()?;

            let file_offset = if block_size > 1
                && (file_offset_raw < (header_size / block_size.max(1))
                    || ((file_offset_raw as u64) < 100_000 && header_size > 100_000))
            {
                (file_offset_raw as u64) * (block_size as u64)
            } else {
                file_offset_raw as u64
            };

            streams.push(PckEntry {
                id,
                block_size,
                file_size,
                file_offset,
                language_id,
                is_soundbank: false,
            });
        }

        Ok(Self {
            header_size,
            version,
            soundbanks,
            streams,
        })
    }

    /// Finds a soundbank entry by its ID.
    pub fn get_soundbank(&self, id: u32) -> Option<&PckEntry> {
        self.soundbanks.iter().find(|e| e.id == id)
    }

    /// Finds a stream entry (.wem) by its ID.
    pub fn get_stream(&self, id: u32) -> Option<&PckEntry> {
        self.streams.iter().find(|e| e.id == id)
    }

    /// Finds an entry by name or numeric string (e.g. "12345", "12345.wem", "12345.bnk").
    pub fn find_entry(&self, identifier: &str) -> Option<&PckEntry> {
        let clean = identifier
            .trim_end_matches(".wem")
            .trim_end_matches(".bnk")
            .trim_end_matches(".wav");

        if let Ok(id) = clean.parse::<u32>() {
            if let Some(entry) = self.get_stream(id) {
                return Some(entry);
            }
            if let Some(entry) = self.get_soundbank(id) {
                return Some(entry);
            }
        }
        None
    }

    /// Extracts the raw binary payload of an entry from the package reader.
    pub fn extract_entry<R: Read + Seek>(
        &self,
        reader: &mut R,
        entry: &PckEntry,
    ) -> Result<Vec<u8>, ExtractError> {
        reader.seek(SeekFrom::Start(entry.file_offset))?;
        let mut buffer = vec![0u8; entry.file_size as usize];
        reader.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    /// Writes a synthetic AKPK archive to a stream for testing and fixture creation.
    pub fn write<W: Write + Seek>(
        writer: &mut W,
        version: u32,
        soundbanks: &[(u32, &[u8])],
        streams: &[(u32, &[u8])],
    ) -> Result<(), ExtractError> {
        let magic = AKPK_MAGIC;
        writer.write_u32::<LittleEndian>(magic)?;

        // Reserve space for header_size (4 bytes), version (4 bytes), lang_size (4 bytes)
        let header_start_pos = writer.stream_position()?;
        writer.write_u32::<LittleEndian>(0)?; // placeholder header_size
        writer.write_u32::<LittleEndian>(version)?;
        writer.write_u32::<LittleEndian>(0)?; // lang_table_size = 0

        // Bank count
        writer.write_u32::<LittleEndian>(soundbanks.len() as u32)?;
        // Stream count
        let mut bank_entries_pos = Vec::new();
        for (id, data) in soundbanks {
            bank_entries_pos.push((*id, data.len() as u32));
            writer.write_u32::<LittleEndian>(*id)?;
            writer.write_u32::<LittleEndian>(1)?; // block_size = 1
            writer.write_u32::<LittleEndian>(data.len() as u32)?;
            writer.write_u32::<LittleEndian>(0)?; // placeholder offset
            writer.write_u32::<LittleEndian>(0)?; // language_id = 0
        }

        writer.write_u32::<LittleEndian>(streams.len() as u32)?;
        let mut stream_entries_pos = Vec::new();
        for (id, data) in streams {
            stream_entries_pos.push((*id, data.len() as u32));
            writer.write_u32::<LittleEndian>(*id)?;
            writer.write_u32::<LittleEndian>(1)?; // block_size = 1
            writer.write_u32::<LittleEndian>(data.len() as u32)?;
            writer.write_u32::<LittleEndian>(0)?; // placeholder offset
            writer.write_u32::<LittleEndian>(0)?; // language_id = 0
        }

        let header_end_pos = writer.stream_position()?;
        let total_header_size = (header_end_pos - 8) as u32;

        // Write payload data
        let mut bank_offsets = Vec::new();
        for (_, data) in soundbanks {
            let offset = writer.stream_position()?;
            bank_offsets.push(offset as u32);
            writer.write_all(data)?;
        }

        let mut stream_offsets = Vec::new();
        for (_, data) in streams {
            let offset = writer.stream_position()?;
            stream_offsets.push(offset as u32);
            writer.write_all(data)?;
        }

        // Go back and update header_size and offsets
        writer.seek(SeekFrom::Start(header_start_pos))?;
        writer.write_u32::<LittleEndian>(total_header_size)?;

        // Skip version (4), lang_size (4), bank_count (4) -> start at header_start_pos + 16
        writer.seek(SeekFrom::Start(header_start_pos + 16))?;
        for &offset in &bank_offsets {
            // Each entry: id (4), block_size (4), file_size (4), offset (4), lang_id (4) -> offset is at +12
            writer.seek(SeekFrom::Current(12))?;
            writer.write_u32::<LittleEndian>(offset)?;
            writer.seek(SeekFrom::Current(4))?;
        }

        // Skip stream_count (4)
        writer.seek(SeekFrom::Current(4))?;
        for &offset in &stream_offsets {
            writer.seek(SeekFrom::Current(12))?;
            writer.write_u32::<LittleEndian>(offset)?;
            writer.seek(SeekFrom::Current(4))?;
        }

        // Seek back to the end
        writer.seek(SeekFrom::End(0))?;
        Ok(())
    }
}

/// Parsed SoundBank Header (`BKHD`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoundBankHeader {
    pub generator_version: u32,
    pub soundbank_id: u32,
}

/// Parses a Wwise SoundBank (`BKHD`) chunk header.
pub fn parse_bkhd(data: &[u8]) -> Result<SoundBankHeader, ExtractError> {
    if data.len() < 16 {
        return Err(ExtractError::InvalidAudio {
            reason: format!(
                "SoundBank data too short for BKHD header (got {} bytes)",
                data.len()
            ),
        });
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != BKHD_MAGIC {
        return Err(ExtractError::InvalidMagic {
            expected: BKHD_MAGIC,
            found: magic,
        });
    }

    let _chunk_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let generator_version = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let soundbank_id = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);

    Ok(SoundBankHeader {
        generator_version,
        soundbank_id,
    })
}

/// Creates a synthetic `BKHD` chunk buffer for testing.
pub fn create_bkhd(generator_version: u32, soundbank_id: u32, extra_payload: &[u8]) -> Vec<u8> {
    let chunk_size = 8 + extra_payload.len() as u32;
    let mut out = Vec::with_capacity(8 + chunk_size as usize);
    out.extend_from_slice(&BKHD_MAGIC.to_le_bytes());
    out.extend_from_slice(&chunk_size.to_le_bytes());
    out.extend_from_slice(&generator_version.to_le_bytes());
    out.extend_from_slice(&soundbank_id.to_le_bytes());
    out.extend_from_slice(extra_payload);
    out
}

/// WAV format specification descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WavSpec {
    pub audio_format: u16,
    pub num_channels: u16,
    pub sample_rate: u32,
    pub byte_rate: u32,
    pub block_align: u16,
    pub bits_per_sample: u16,
}

impl WavSpec {
    /// Creates a PCM WAV specification.
    pub fn pcm(sample_rate: u32, num_channels: u16, bits_per_sample: u16) -> Self {
        let block_align = num_channels * (bits_per_sample / 8).max(1);
        let byte_rate = sample_rate * (block_align as u32);
        Self {
            audio_format: WAVE_FORMAT_PCM,
            num_channels,
            sample_rate,
            byte_rate,
            block_align,
            bits_per_sample,
        }
    }

    /// Creates an ADPCM WAV specification.
    pub fn adpcm(sample_rate: u32, num_channels: u16, bits_per_sample: u16) -> Self {
        let block_align = num_channels * (bits_per_sample / 8).max(1);
        let byte_rate = sample_rate * (block_align as u32);
        Self {
            audio_format: WAVE_FORMAT_MS_ADPCM,
            num_channels,
            sample_rate,
            byte_rate,
            block_align,
            bits_per_sample,
        }
    }
}

/// Wraps raw PCM or ADPCM audio samples with standard RIFF, WAVE, fmt, and data chunks.
pub fn export_to_wav(spec: &WavSpec, samples: &[u8]) -> Vec<u8> {
    let mut wav = Vec::with_capacity(44 + samples.len());

    // 0..4: "RIFF"
    wav.extend_from_slice(b"RIFF");

    // 4..8: File size minus 8 bytes
    let riff_size = (36 + samples.len()) as u32;
    wav.extend_from_slice(&riff_size.to_le_bytes());

    // 8..12: "WAVE"
    wav.extend_from_slice(b"WAVE");

    // 12..16: "fmt "
    wav.extend_from_slice(b"fmt ");

    // 16..20: fmt chunk size (16 for PCM / basic fmt)
    wav.extend_from_slice(&16u32.to_le_bytes());

    // 20..22: Audio format (1 = PCM, 2 = MS-ADPCM)
    wav.extend_from_slice(&spec.audio_format.to_le_bytes());

    // 22..24: Num channels
    wav.extend_from_slice(&spec.num_channels.to_le_bytes());

    // 24..28: Sample rate
    wav.extend_from_slice(&spec.sample_rate.to_le_bytes());

    // 28..32: Byte rate
    wav.extend_from_slice(&spec.byte_rate.to_le_bytes());

    // 32..34: Block align
    wav.extend_from_slice(&spec.block_align.to_le_bytes());

    // 34..36: Bits per sample
    wav.extend_from_slice(&spec.bits_per_sample.to_le_bytes());

    // 36..40: "data"
    wav.extend_from_slice(b"data");

    // 40..44: Data chunk size
    wav.extend_from_slice(&(samples.len() as u32).to_le_bytes());

    // 44..: Raw audio samples
    wav.extend_from_slice(samples);

    wav
}

/// Inspects and parses a RIFF WAVE file buffer, returning its spec and sample slice.
pub fn parse_wav(data: &[u8]) -> Result<(WavSpec, &[u8]), ExtractError> {
    if data.len() < 44 {
        return Err(ExtractError::InvalidAudio {
            reason: format!("WAV buffer too small: {} bytes", data.len()),
        });
    }

    let riff_magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if riff_magic != RIFF_MAGIC {
        return Err(ExtractError::InvalidMagic {
            expected: RIFF_MAGIC,
            found: riff_magic,
        });
    }

    let wave_magic = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if wave_magic != WAVE_MAGIC {
        return Err(ExtractError::InvalidMagic {
            expected: WAVE_MAGIC,
            found: wave_magic,
        });
    }

    // Walk chunks
    let mut cursor = 12;
    let mut found_fmt = None;
    let mut found_data = None;

    while cursor + 8 <= data.len() {
        let chunk_id = u32::from_le_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
        ]);
        let chunk_size = u32::from_le_bytes([
            data[cursor + 4],
            data[cursor + 5],
            data[cursor + 6],
            data[cursor + 7],
        ]) as usize;
        cursor += 8;

        if chunk_id == FMT_MAGIC && chunk_size >= 16 {
            if cursor + 16 > data.len() {
                break;
            }
            let audio_format = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
            let num_channels = u16::from_le_bytes([data[cursor + 2], data[cursor + 3]]);
            let sample_rate = u32::from_le_bytes([
                data[cursor + 4],
                data[cursor + 5],
                data[cursor + 6],
                data[cursor + 7],
            ]);
            let byte_rate = u32::from_le_bytes([
                data[cursor + 8],
                data[cursor + 9],
                data[cursor + 10],
                data[cursor + 11],
            ]);
            let block_align = u16::from_le_bytes([data[cursor + 12], data[cursor + 13]]);
            let bits_per_sample = u16::from_le_bytes([data[cursor + 14], data[cursor + 15]]);

            found_fmt = Some(WavSpec {
                audio_format,
                num_channels,
                sample_rate,
                byte_rate,
                block_align,
                bits_per_sample,
            });
        } else if chunk_id == DATA_MAGIC {
            let end = (cursor + chunk_size).min(data.len());
            found_data = Some(&data[cursor..end]);
        }

        cursor += chunk_size;
        // Pad to word boundary
        #[allow(clippy::manual_is_multiple_of)]
        if chunk_size % 2 != 0 {
            cursor += 1;
        }
    }

    let spec = found_fmt.ok_or_else(|| ExtractError::InvalidAudio {
        reason: "Missing fmt chunk in WAV buffer".to_string(),
    })?;
    let samples = found_data.ok_or_else(|| ExtractError::InvalidAudio {
        reason: "Missing data chunk in WAV buffer".to_string(),
    })?;

    Ok((spec, samples))
}

/// Converts a `.wem` stream buffer into a valid standard `.wav` file buffer.
/// If the stream already has a RIFF container, it extracts and re-wraps to ensure compatibility.
/// If raw stream, wraps with default 48kHz 16-bit stereo PCM (or provided spec).
pub fn convert_wem_to_wav(
    wem_data: &[u8],
    fallback_spec: Option<WavSpec>,
) -> Result<Vec<u8>, ExtractError> {
    if wem_data.len() >= 12 && &wem_data[0..4] == b"RIFF" && &wem_data[8..12] == b"WAVE" {
        // Parse RIFF structure
        let (spec, samples) = parse_wav(wem_data)?;
        Ok(export_to_wav(&spec, samples))
    } else {
        let spec = fallback_spec.unwrap_or_else(|| WavSpec::pcm(48000, 2, 16));
        Ok(export_to_wav(&spec, wem_data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_bkhd_parsing() {
        let extra = [1, 2, 3, 4];
        let bank_data = create_bkhd(120, 98765432, &extra);
        let header = parse_bkhd(&bank_data).unwrap();
        assert_eq!(header.generator_version, 120);
        assert_eq!(header.soundbank_id, 98765432);
    }

    #[test]
    fn test_wav_export_and_parse_roundtrip() {
        let spec = WavSpec::pcm(44100, 2, 16);
        let samples = [0x12, 0x34, 0x56, 0x78].repeat(100);
        let wav = export_to_wav(&spec, &samples);

        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");

        let (parsed_spec, parsed_samples) = parse_wav(&wav).unwrap();
        assert_eq!(parsed_spec, spec);
        assert_eq!(parsed_samples, samples.as_slice());
    }

    #[test]
    fn test_pck_archive_roundtrip() {
        let bank1_data = create_bkhd(112, 1001, &[10, 20]);
        let stream1_data = export_to_wav(&WavSpec::pcm(48000, 1, 16), &[1, 2, 3, 4]);
        let stream2_data = vec![0xEE; 128];

        let mut pck_stream = Cursor::new(Vec::new());
        PckArchive::write(
            &mut pck_stream,
            1,
            &[(1001, &bank1_data)],
            &[(2001, &stream1_data), (2002, &stream2_data)],
        )
        .unwrap();

        pck_stream.seek(SeekFrom::Start(0)).unwrap();
        let archive = PckArchive::read(&mut pck_stream).unwrap();

        assert_eq!(archive.soundbanks.len(), 1);
        assert_eq!(archive.streams.len(), 2);

        let bank_entry = archive.get_soundbank(1001).expect("Bank 1001 not found");
        let stream_entry = archive.get_stream(2001).expect("Stream 2001 not found");

        let extracted_bank = archive.extract_entry(&mut pck_stream, bank_entry).unwrap();
        assert_eq!(extracted_bank, bank1_data);

        let extracted_stream = archive
            .extract_entry(&mut pck_stream, stream_entry)
            .unwrap();
        assert_eq!(extracted_stream, stream1_data);

        // Test convert_wem_to_wav
        let converted_wav = convert_wem_to_wav(&extracted_stream, None).unwrap();
        let (spec, _) = parse_wav(&converted_wav).unwrap();
        assert_eq!(spec.sample_rate, 48000);
        assert_eq!(spec.num_channels, 1);
    }
}
