///
/// Handles save/restore from the Quetzal format
/// http://inform-fiction.org/zmachine/standards/quetzal/index.html
///
pub mod iff;

use crate::interfaces::QuetzalData;
use iff::{get_chunk_id_as_str, load_iff_chunks_from_bytes, save_iff_chunks_to_bytes, IffChunk};

pub struct QuetzalStoryInfo {
    pub release_number: u16,
    pub serial_number: [u8; 6],
    pub checksum: u16,
    pub initial_pc: usize,
}

pub fn queztal_data_to_bytes(data: QuetzalData) -> Vec<u8> {
    let mut form_chunks = vec![IffChunk::IFhd {
        release_number: data.release_number,
        serial_number: data.serial,
        checksum: data.checksum,
        initial_pc: data.initial_pc,
    }];

    if data.data_is_compressed {
        form_chunks.push(IffChunk::CMem(data.data.clone()));
    } else {
        form_chunks.push(IffChunk::UMem(data.data.clone()));
    }

    form_chunks.push(IffChunk::Stks(data.stack_frames));

    let form_chunk = IffChunk::FORM([b'I', b'F', b'Z', b'S'], form_chunks);
    let chunks = vec![form_chunk];
    save_iff_chunks_to_bytes(chunks).unwrap()
}

///
pub struct QuetzalRestoreHandler {}

impl QuetzalRestoreHandler {
    pub fn from_bytes(data: Vec<u8>) -> Result<QuetzalData, String> {
        match load_iff_chunks_from_bytes(&data) {
            Err(msg) => Err(format!("Error parsing IFF: {}", msg)),
            Ok(chunks) => {
                let mut queztal_data = QuetzalData {
                    release_number: 0,
                    serial: [0, 0, 0, 0, 0, 0],
                    checksum: 0,
                    initial_pc: 0,
                    data_is_compressed: false,
                    stack_frames: vec![],
                    data: vec![],
                };

                // The file will consist of a FORM chunk of "IFZS"
                let mut form_chunks: Option<Vec<IffChunk>> = None;

                for chunk in chunks {
                    if let IffChunk::FORM(chunk_id, chunks) = chunk {
                        match form_chunks {
                            None => {
                                if get_chunk_id_as_str(&chunk_id) != "IFZS" {
                                    return Err(format!(
                                        "Invalid file: expected IFZS, found {}",
                                        get_chunk_id_as_str(&chunk_id)
                                    ));
                                }
                                form_chunks = Some(chunks);
                            }
                            Some(_) => {
                                return Err(String::from("Multiple form chunks found"));
                            }
                        }
                    }
                }

                match form_chunks {
                    None => Err(String::from("No form chunk found")),
                    Some(chunks) => {
                        for chunk in chunks {
                            match chunk {
                                IffChunk::IFhd {
                                    release_number,
                                    serial_number,
                                    checksum,
                                    initial_pc,
                                } => {
                                    queztal_data.release_number = release_number;
                                    queztal_data.checksum = checksum;
                                    queztal_data.initial_pc = initial_pc;
                                    queztal_data.serial = serial_number;
                                }
                                IffChunk::Stks(frames) => {
                                    queztal_data.stack_frames = frames.clone();
                                }
                                IffChunk::CMem(data) => {
                                    queztal_data.data_is_compressed = true;
                                    queztal_data.data = data.clone();
                                }
                                IffChunk::UMem(data) => {
                                    queztal_data.data_is_compressed = false;
                                    queztal_data.data = data.clone();
                                }
                                _ => (),
                            }
                        }
                        Ok(queztal_data)
                    }
                }
            }
        }
    }
}
