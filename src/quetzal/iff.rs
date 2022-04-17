/// Implementation of the IFF file format specifically designed for use with the
/// Quetzal save format
///
/// See http://inform-fiction.org/zmachine/standards/quetzal/index.html
///
/// It could easily be expanded to handle other chunk types.
const CHUNK_HEADER_SIZE: usize = 8;

pub fn get_chunk_id_as_str(chunk_id: &[u8; 4]) -> &str {
    std::str::from_utf8(chunk_id).unwrap()
}

#[derive(Clone, Debug)]
pub struct QueztalStackFrame {
    pub return_pc: usize,
    pub flags: u8,
    pub result_var: u8,
    pub arguments: u8,
    pub local_variables: Vec<u16>,
    pub evaluation_stack: Vec<u16>,
}

#[derive(Clone, Debug)]
#[allow(clippy::upper_case_acronyms)] // The upper case is part of the IFF spec
pub enum IffChunk {
    Error(String), // If an internal chunk can't be correctly handled
    Generic {
        chunk_id: [u8; 4],
        data: Vec<u8>,
    }, // For unknown types
    FORM([u8; 4], Vec<IffChunk>), // FORM is a special case that contains other chunks,

    // Quetzal chunks - part of the Quetzal spec
    CMem(Vec<u8>),                // Compressed story data
    UMem(Vec<u8>),                // Uncompressed story data
    Stks(Vec<QueztalStackFrame>), // Stack frames
    IFhd {
        release_number: u16,
        serial_number: [u8; 6],
        checksum: u16,
        initial_pc: usize,
    },
    AUTH(Vec<u8>), // Name of file author.
    C___(Vec<u8>), // Copyright message. This is really (c)_ but can't rep as enum
    ANNO(Vec<u8>), // Textual annotation
    IntD {
        os_id: [u8; 4],
        flags: u8,
        contents_id: u8,
        reserved: u16,
        interpreter_id: [u8; 4],
        data: Vec<u8>,
    },
}

/// Utilities for loading/saving form elements
fn get_three_byte_usize(data: &[u8], offset: usize) -> (usize, usize) {
    (
        (((data[offset] as usize) << 16)
            + ((data[offset + 1] as usize) << 8)
            + (data[offset + 2] as usize)),
        offset + 3,
    )
}

fn get_word(data: &[u8], offset: usize) -> (u16, usize) {
    (
        (((data[offset] as u16) << 8) + (data[offset + 1] as u16)),
        offset + 2,
    )
}

fn get_byte(data: &[u8], offset: usize) -> (u8, usize) {
    (data[offset], offset + 1)
}

fn get_six_byte_array(data: &[u8], offset: usize) -> ([u8; 6], usize) {
    (
        [
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
        ],
        offset + 6,
    )
}

fn get_four_byte_array(data: &[u8], offset: usize) -> ([u8; 4], usize) {
    (
        [
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ],
        offset + 4,
    )
}

struct IffWriter {
    data: Vec<u8>,
}

impl IffWriter {
    fn write_data(&mut self, data: &[u8]) {
        for b in data.iter() {
            self.data.push(*b);
        }
    }

    fn write_word_data(&mut self, data: &[u16]) {
        for w in data.iter() {
            self.write_word(*w);
        }
    }

    fn write_four_byte_array(&mut self, a: [u8; 4]) {
        for b in a.iter() {
            self.data.push(*b);
        }
    }

    fn write_six_byte_array(&mut self, a: [u8; 6]) {
        for b in a.iter() {
            self.data.push(*b);
        }
    }

    fn write_byte(&mut self, b: u8) {
        self.data.push(b);
    }

    fn write_word(&mut self, w: u16) {
        self.data.push(((w & 0xff00) >> 8) as u8);
        self.data.push((w & 0x00ff) as u8);
    }

    fn write_three_byte_u32(&mut self, u: u32) {
        self.data.push(((u & 0xff0000) >> 16) as u8);
        self.data.push(((u & 0x00ff00) >> 8) as u8);
        self.data.push((u & 0x0000ff) as u8);
    }
}

pub fn handle_chunk(chunk: &GenericChunk) -> IffChunk {
    match chunk.get_chunk_id_as_str() {
        "ANNO" => IffChunk::ANNO(chunk.data.clone()),
        "AUTH" => IffChunk::AUTH(chunk.data.clone()),
        "(c)_" => IffChunk::C___(chunk.data.clone()),
        "CMem" => IffChunk::CMem(chunk.data.clone()),
        "UMem" => IffChunk::UMem(chunk.data.clone()),
        "IntD" => {
            let (os_id, offset) = get_four_byte_array(&chunk.data, 0);
            let (flags, offset) = get_byte(&chunk.data, offset);
            let (contents_id, offset) = get_byte(&chunk.data, offset);
            let (reserved, offset) = get_word(&chunk.data, offset);
            let (interpreter_id, offset) = get_four_byte_array(&chunk.data, offset);
            IffChunk::IntD {
                os_id,
                flags,
                contents_id,
                reserved,
                interpreter_id,
                data: chunk.data[offset..].to_vec(),
            }
        }
        "IFhd" => {
            let (release_number, offset) = get_word(&chunk.data, 0);
            let (serial_number, offset) = get_six_byte_array(&chunk.data, offset);
            let (checksum, offset) = get_word(&chunk.data, offset);
            let (initial_pc, _) = get_three_byte_usize(&chunk.data, offset);

            IffChunk::IFhd {
                release_number,
                serial_number,
                checksum,
                initial_pc,
            }
        }
        "Stks" => {
            let mut stacks = Vec::new();

            let mut base_offset = 0;

            while base_offset < chunk.data.len() {
                let (return_pc, offset) = get_three_byte_usize(&chunk.data, base_offset);
                let (flags, offset) = get_byte(&chunk.data, offset);
                // 4.6 -- only bottom 4 bits matter
                let variable_count = flags & 0x0f;
                let (result_var, offset) = get_byte(&chunk.data, offset);
                let (arguments, offset) = get_byte(&chunk.data, offset);
                let (n, offset) = get_word(&chunk.data, offset);
                let mut local_variables = Vec::new();
                base_offset = offset;
                for _ in 0..variable_count {
                    let (v, offset) = get_word(&chunk.data, base_offset);
                    base_offset = offset;
                    local_variables.push(v);
                }
                let mut evaluation_stack = Vec::new();
                for _ in 0..n {
                    let (s, offset) = get_word(&chunk.data, base_offset);
                    base_offset = offset;
                    evaluation_stack.push(s);
                }
                stacks.push(QueztalStackFrame {
                    return_pc,
                    flags,
                    result_var,
                    arguments,
                    local_variables,
                    evaluation_stack,
                })
            }

            IffChunk::Stks(stacks)
        }

        _ => IffChunk::Generic {
            chunk_id: chunk.chunk_id,
            data: chunk.data.clone(),
        },
    }
}

pub fn load_iff_chunks_from_bytes(data: &[u8]) -> Result<Vec<IffChunk>, &'static str> {
    let mut offset: usize = 0;
    let mut results: Vec<IffChunk> = vec![];
    let l = data.len();

    while offset < l {
        let chunk = GenericChunk::from_bytes(data, offset as u32)?;
        let block_size: u32 = chunk.get_block_size();
        results.push(match chunk.get_chunk_id_as_str() {
            "FORM" => match FORMChunk::from_bytes(data, (offset + CHUNK_HEADER_SIZE) as u32) {
                Err(msg) => IffChunk::Error(format!("Error parsing IFF FORM chunk: {}", msg)),
                Ok(form_chunk) => {
                    let mut form_chunks = Vec::new();
                    for generic_chunk in form_chunk.chunks {
                        form_chunks.push(handle_chunk(&generic_chunk));
                    }
                    IffChunk::FORM(form_chunk.chunk_id, form_chunks)
                }
            },
            _ => handle_chunk(&chunk),
        });
        offset += block_size as usize;
    }

    Ok(results)
}

// Truncated chars are fine in this case since only the 8-bit version is wanted
#[allow(clippy::char_lit_as_u8)]
fn add_chunk_to_data(chunk: &IffChunk, writer: &mut IffWriter) {
    let generic_chunk: GenericChunk = match chunk {
        IffChunk::IFhd {
            release_number,
            serial_number,
            checksum,
            initial_pc,
        } => {
            let mut writer = IffWriter { data: vec![] };
            writer.write_word(*release_number);
            writer.write_six_byte_array(*serial_number);
            writer.write_word(*checksum);
            writer.write_three_byte_u32(*initial_pc as u32);

            let data_len = writer.data.len() as u32;
            GenericChunk {
                chunk_id: ['I' as u8, 'F' as u8, 'h' as u8, 'd' as u8],
                data: writer.data,
                data_size: data_len,
            }
        }
        IffChunk::IntD {
            os_id,
            flags,
            contents_id,
            reserved,
            interpreter_id,
            data,
        } => {
            let mut writer = IffWriter { data: vec![] };
            writer.write_four_byte_array(*os_id);
            writer.write_byte(*flags);
            writer.write_byte(*contents_id);
            writer.write_word(*reserved);
            writer.write_four_byte_array(*interpreter_id);
            writer.write_data(data);
            let data_len = writer.data.len() as u32;
            GenericChunk {
                chunk_id: ['I' as u8, 'n' as u8, 't' as u8, 'D' as u8],
                data: writer.data,
                data_size: data_len as u32,
            }
        }
        IffChunk::Stks(frames) => {
            let mut writer = IffWriter { data: vec![] };
            for frame in frames {
                writer.write_three_byte_u32(frame.return_pc as u32);
                writer.write_byte(frame.flags);
                writer.write_byte(frame.result_var);
                writer.write_byte(frame.arguments);
                writer.write_word(frame.evaluation_stack.len() as u16);
                writer.write_word_data(&frame.local_variables);
                writer.write_word_data(&frame.evaluation_stack);
            }
            let data_len = writer.data.len() as u32;
            GenericChunk {
                chunk_id: ['S' as u8, 't' as u8, 'k' as u8, 's' as u8],
                data: writer.data,
                data_size: data_len as u32,
            }
        }
        IffChunk::FORM(form_id, form_chunks) => {
            let mut form_writer = IffWriter { data: vec![] };

            form_writer.write_four_byte_array(*form_id);
            for form_chunk in form_chunks {
                add_chunk_to_data(form_chunk, &mut form_writer);
            }
            let data_len = form_writer.data.len() as u32;
            GenericChunk {
                chunk_id: ['F' as u8, 'O' as u8, 'R' as u8, 'M' as u8],
                data: form_writer.data,
                data_size: data_len,
            }
        }
        IffChunk::ANNO(text) => GenericChunk {
            chunk_id: ['A' as u8, 'N' as u8, 'N' as u8, 'O' as u8],
            data: text.clone(),
            data_size: text.len() as u32,
        },
        IffChunk::C___(text) => GenericChunk {
            chunk_id: ['C' as u8, ' ' as u8, ' ' as u8, ' ' as u8],
            data: text.clone(),
            data_size: text.len() as u32,
        },
        IffChunk::AUTH(text) => GenericChunk {
            chunk_id: ['A' as u8, 'U' as u8, 'T' as u8, 'H' as u8],
            data: text.clone(),
            data_size: text.len() as u32,
        },
        IffChunk::UMem(data) => GenericChunk {
            chunk_id: ['U' as u8, 'M' as u8, 'e' as u8, 'm' as u8],
            data: data.clone(),
            data_size: data.len() as u32,
        },
        IffChunk::CMem(data) => GenericChunk {
            chunk_id: ['C' as u8, 'M' as u8, 'e' as u8, 'm' as u8],
            data: data.clone(),
            data_size: data.len() as u32,
        },
        IffChunk::Generic { chunk_id, data } => GenericChunk {
            chunk_id: *chunk_id,
            data: data.clone(),
            data_size: data.len() as u32,
        },
        IffChunk::Error(_) => GenericChunk {
            chunk_id: ['N' as u8, 'U' as u8, 'L' as u8, 'L' as u8],
            data: vec![],
            data_size: 0,
        },
    };

    for b in generic_chunk.to_bytes() {
        writer.write_byte(b);
    }
}

pub fn save_iff_chunks_to_bytes(chunks: Vec<IffChunk>) -> Result<Vec<u8>, &'static str> {
    let mut writer = IffWriter { data: vec![] };
    for chunk in chunks {
        add_chunk_to_data(&chunk, &mut writer);
    }

    Ok(writer.data)
}

//
pub trait Chunk {
    fn to_bytes(&self) -> Vec<u8>;
}

/// A generic chunk has a 4-byte id and raw data
pub struct GenericChunk {
    pub chunk_id: [u8; 4],
    pub data: Vec<u8>,
    pub data_size: u32,
}

impl Chunk for GenericChunk {
    fn to_bytes(&self) -> Vec<u8> {
        let mut chunk_bytes = Vec::new();

        // ID
        for i in 0..4 {
            chunk_bytes.push(self.chunk_id[i]);
        }

        // Size
        chunk_bytes.push(((self.data_size & 0xff00_0000) >> 24) as u8);
        chunk_bytes.push(((self.data_size & 0x00ff_0000) >> 16) as u8);
        chunk_bytes.push(((self.data_size & 0x0000_ff00) >> 8) as u8);
        chunk_bytes.push((self.data_size & 0x0000_00ff) as u8);

        // Data
        for b in self.data.iter() {
            chunk_bytes.push(*b);
        }

        // Always need to pad to even number of bytes per spec. Note this
        // is not included in the chunk length
        if chunk_bytes.len() % 2 == 1 {
            chunk_bytes.push(0);
        }
        chunk_bytes
    }
}

impl GenericChunk {
    pub fn from_bytes(data: &[u8], offset: u32) -> Result<GenericChunk, &'static str> {
        let usize_offset = offset as usize;

        if usize_offset + 8 >= data.len() {
            return Err("No more space for chunks.");
        }

        let mut chunk = GenericChunk {
            chunk_id: [
                data[usize_offset],
                data[usize_offset + 1],
                data[usize_offset + 2],
                data[usize_offset + 3],
            ],
            data: Vec::new(),
            data_size: data[usize_offset + 7] as u32
                + ((data[usize_offset + 6] as u32) << 8)
                + ((data[usize_offset + 5] as u32) << 16)
                + ((data[usize_offset + 4] as u32) << 24),
        };

        let data_offset = offset + 8;
        for idx in 0..chunk.data_size {
            chunk.data.push(data[data_offset as usize + idx as usize]);
        }

        Ok(chunk)
    }

    pub fn get_chunk_id_as_str(&self) -> &str {
        get_chunk_id_as_str(&self.chunk_id)
    }

    pub fn get_block_size(&self) -> u32 {
        // 4 bytes for chunk id
        // 4 bytes for 32-bit size
        // then data size
        // then possible padding
        let base_size = 4 + 4 + self.data_size;
        if self.data_size % 2 == 0 {
            base_size
        } else {
            base_size + 1
        }
    }
}

/// A "FORM" type chunk, consisting of a list of other chunks and a type

#[allow(clippy::upper_case_acronyms)] // The upper case is part of the IFF spec
pub struct FORMChunk {
    pub chunk_id: [u8; 4],
    pub chunks: Vec<GenericChunk>,
}

impl Chunk for FORMChunk {
    fn to_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

impl FORMChunk {
    pub fn get_chunk_id_as_str(&self) -> &str {
        get_chunk_id_as_str(&self.chunk_id)
    }

    pub fn from_bytes(data: &[u8], offset: u32) -> Result<FORMChunk, &'static str> {
        let usize_offset = offset as usize;
        if data.len() < usize_offset {
            return Err("FORM chunk must be at least length 4.");
        }

        let mut form_chunk = FORMChunk {
            chunk_id: [
                data[usize_offset],
                data[usize_offset + 1],
                data[usize_offset + 2],
                data[usize_offset + 3],
            ],
            chunks: Vec::new(),
        };

        let mut data_offset = usize_offset + 4;
        let l = data.len();
        while data_offset < l {
            let chunk = GenericChunk::from_bytes(data, data_offset as u32)?;
            let chunk_len = chunk.get_block_size();
            if chunk_len == 0 {
                return Err("FORM Contains zero-size chunk");
            }
            data_offset += chunk_len as usize;

            form_chunk.chunks.push(chunk);
        }

        Ok(form_chunk)
    }
}
