use crate::instructions::{
    handle_instruction, word_to_signed, Action, DebugVerbosity, InputStreamEnum, MemoryReader,
    ObjectTreeReader, OutputStreamEnum, Property, ZCodeVersion, ZmachineError, BYTE_LENGTH,
    WORD_LENGTH, ZMACHINE_FALSE, ZMACHINE_TRUE,
};
use crate::interfaces::{QuetzalData, TerpIO};
use crate::quetzal::iff::QueztalStackFrame;
use crate::story::{
    StatusMode, ZCharacterMapper, ZCharacterMapperStub, ZCharacterMapperV2, ZCharacterMapperV3,
    A0_CHARS, A2_CHARS, ABBREV_1, ABBREV_2, ABBREV_3, DEFAULT_UNICODE_MAPPING, NOPRINT_CHAR,
    SHIFT_DOWN, SHIFT_LOCK_DOWN, TOGGLE_EXTENDED,
};
use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::cmp;

const MAX_LENGTH_V1TO3: usize = 1024 * 128;
const OBJECT_ENTRY_SIZE_V3: usize = 9;
const MAX_OBJECT_V3: usize = 255;

const HEADER_VERSION: usize = 0x00;
const HEADER_FLAGS_1: usize = 0x01;
const HEADER_HIGHMEM_ADDRESS: usize = 0x04;
const HEADER_PC_ADDRESS: usize = 0x06;
const HEADER_DICTIONARY_ADDRESS: usize = 0x08;
const HEADER_OBJECT_ADDRESS: usize = 0x0A;
const HEADER_GLOBALS_ADDRESS: usize = 0x0C;
const HEADER_STATIC_ADDRESS: usize = 0x0E;
pub const HEADER_FLAGS_2: usize = 0x10;
const HEADER_ABBREVS_ADDRESS: usize = 0x18;
const HEADER_FILE_LENGTH: usize = 0x1A;
const HEADER_CHECKSUM: usize = 0x1C;
const HEADER_RELEASE_NUMBER: usize = 0x02;
const HEADER_SERIAL: usize = 0x12;
const HEADER_REVISION_NUMBER: usize = 0x32;
const HEADER_INFORM_VERSION: usize = 0x3C;
const HEADER_TOP: usize = 0x20;

const HEADER_STATUS_BIT: u8 = 1;
const HEADER_STATUS_NOT_AVAILABLE_BIT: u8 = 4;
const HEADER_SCREEN_SPLIT_AVAILABLE_BIT: u8 = 5;
const HEADER_VARIABLE_PITCH_BIT: u8 = 6;

const V123_FILE_LENGTH_MULTIPLIER: usize = 2;

const MINIMUM_SIZE: usize = 0x64; // If shorter than header, not a valid file

pub const OBJECT_NOTHING: usize = 0; // Nothing object is 0
const OBJECT_TABLE_PARENT_OFFSET: usize = 4;
const OBJECT_TABLE_SIBLING_OFFSET: usize = 5;
const OBJECT_TABLE_CHILD_OFFSET: usize = 6;
const OBJECT_TABLE_PROPERTIES_OFFSET: usize = 7;
const MIN_DICTIONARY_ENTRY_LENGTH_V123: usize = 4; // 13.2
const DICTIONARY_WORD_SIZE_V123: usize = 4; // 13.3
const DICTIONARY_WORD_SIZE: usize = 6; // 13.4
const OBJECT_TABLE_MAX_CYCLE: usize = 1000;
const MAX_PROPERTY_123: usize = 31;
const MAX_WORD_LENGTH: usize = 65535;
const STACK_VARIABLE: u8 = 0;
const MAX_LOCAL_VAR: u8 = 15;
pub const GLOBAL_1: u8 = 16;
pub const GLOBAL_2: u8 = 17;
pub const GLOBAL_3: u8 = 18;

const ASCII_BACKSPACE: u8 = 8;
const ASCII_NEWLINE: u8 = 10;
const ASCII_ESCAPE: u8 = 27;

const ZSCII_DELETE: u8 = 8;
const ZSCII_NEWLINE: u8 = 10;
const ZSCII_ESCAPE: u8 = 27;
const ZSCII_SPACE: u8 = 32;

const MAX_MEMORY_STREAM_SIZE: usize = 16;

pub enum ErrorMode {
    Ignore,
    Panic,
}

#[derive(Debug, PartialEq)]
pub enum VMLoadError {
    StoryFileTooSmall(usize),
    StoryFileTooLarge(usize),
    UnsupportedVersion(),
    ChecksumMismatch(),
    LengthMismatch(),
    InterpreterError(String),
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum VMState {
    Initializing,
    Running,
    WaitingForInput(usize, u16, u16), // next PC address, text buffer address, and parse address
    Quit,
    Error,
    // When waiting to save/restore a game
    RestorePrompt,
    SavePrompt(usize, usize), // PC after success and PC after failure
    // These states all occur when waiting for a stream
    TranscriptPrompt,
    CommandOutputPrompt,
    CommandInputPrompt,
}

///
/// All execution happens in the context of a "routine" (see sections 5/6).
///
/// All variables are 2-byte words.
///
/// Routines have 1-15 local variables, as well as a stack (variable 0)
///
struct Routine {
    /// Start address for the routine instructions. Can be same as header address
    code_address: usize,
    /// Where to return after the routine
    return_to: usize,
    /// Var number to store return value into
    store_var: u8,
    /// Local variables
    local_variables: Vec<u16>,
    /// Stack index at start of routine
    stack_pointer: usize,
    /// Used for v4 and up. Indicates results should be discarded
    discard: bool,
}

impl Routine {
    ///
    /// Returns a routine with empty stack and locals and the provided addresses
    /// Does not attempt to parse the header
    ///
    pub fn create_empty(code_address: usize, return_to: usize) -> Routine {
        Routine {
            code_address,
            return_to,
            store_var: 0,
            local_variables: Vec::new(),
            stack_pointer: 0,
            discard: false,
        }
    }
    ///
    /// Create a routine with existing data
    /// Used as part of restore a call stack in undo
    ///
    pub fn create_from_data(
        code_address: usize,
        return_to: usize,
        locals: Vec<u16>,
        store_var: u8,
        stack_pointer: usize,
    ) -> Routine {
        Routine {
            code_address,
            store_var,
            return_to,
            local_variables: locals,
            stack_pointer,
            discard: false,
        }
    }

    ///
    /// Returns a routine starting at the given address. This will initialize
    /// the local variables as per 5.2.1
    pub fn create_from_address<T: MemoryReader>(
        address: usize,
        return_to: usize,
        arguments: Vec<u16>,
        store_var: u8,
        reader: &T,
        version: ZCodeVersion,
    ) -> Result<Routine, ZmachineError> {
        let mut routine = Routine {
            code_address: address + 1,
            store_var,
            return_to,
            local_variables: Vec::new(),
            discard: false,
            stack_pointer: reader.get_stack_pointer(), // 6.3.1 note start of stack
        };

        // First byte of routine is number of locals. See 5.2.1.
        let var_count = reader.get_byte(address)? as usize;
        if var_count > 15 {
            return Err(ZmachineError::RoutineLocalVariableOutOfBounds(var_count));
        }

        match version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                for i in 0..var_count {
                    if i < arguments.len() {
                        routine.local_variables.push(arguments[i]);
                    } else {
                        routine
                            .local_variables
                            .push(reader.get_word(address + BYTE_LENGTH + (i * WORD_LENGTH))?);
                    }
                }
            }
        }

        routine.code_address = address + BYTE_LENGTH + (var_count * WORD_LENGTH);

        Ok(routine)
    }

    /// Return a string representing the state of this routine
    /// Useful for debugging
    pub fn get_state_string(&self) -> String {
        let mut checksum: usize = 0;
        for local in self.local_variables.iter() {
            checksum += (*local) as usize;
        }

        format!(
            "S:{:02X} RT:{:06X} LC: {} CS: {:04X}",
            self.store_var,
            self.return_to,
            self.local_variables.len(),
            checksum % u32::max_value() as usize
        )
    }
}

///
/// Return both a string and the address for the end of the string
///
struct StringAndAddress {
    address: usize,
    string: String,
}

#[derive(Clone, PartialEq, Debug)]
pub struct DictionaryWord {
    pub address: usize,
    pub text: String,
}

pub struct IndexedWord {
    pub word: Vec<u8>,
    pub index: usize,
}

trait ZMachineRNG {
    fn next_value(&mut self, max_value: u16) -> u16;
}

struct RandomModeRNG {}

impl ZMachineRNG for RandomModeRNG {
    fn next_value(&mut self, max_value: u16) -> u16 {
        let v: u16 = thread_rng().gen();
        (v % max_value) + 1 // Min value is 1
    }
}

struct PredicatableRNG {
    sequence: u32,
    seed: u16,
}

impl ZMachineRNG for PredicatableRNG {
    fn next_value(&mut self, max_value: u16) -> u16 {
        // See Remarks section at end of section 2
        let v = self.sequence % (self.seed as u32);
        self.sequence += 1;
        ((v % max_value as u32) + 1) as u16 // Min value is 1
    }
}

struct SeededRNG {
    rng: ChaCha20Rng,
}

impl ZMachineRNG for SeededRNG {
    fn next_value(&mut self, max_value: u16) -> u16 {
        // See Remarks section at end of section 2
        let v: u16 = self.rng.gen();
        (v % max_value) + 1 // Min value is 1
    }
}

pub struct VM {
    version: ZCodeVersion,
    story: Vec<u8>,
    memory: Vec<u8>,
    routine_stack: Vec<Routine>,
    stack: Vec<u16>,
    state: VMState,
    pc: usize,
    rng: Box<dyn ZMachineRNG>,

    // Used internally and initialized from header.
    high_memory_address: u16,
    initial_pc_address: u16,
    dictionary_address: u16,
    global_variable_address: u16,
    static_memory_address: u16,
    abbrev_table_address: u16,
    object_table_address: u16,
    object_tree_address: u16,
    file_length: usize,
    checksum: u16,
    release_number: u16,
    serial: String,
    serial_raw: [u8; 6],
    inform_version: String,

    // Misc
    status_mode: StatusMode,
    text_mapper: Box<dyn ZCharacterMapper>,
    dictionary_words: Vec<DictionaryWord>,
    dictionary_word_separators: Vec<u8>,
    dictionary_entry_length: usize,
    memory_stream_stack: Vec<u16>,

    // For preserving flags across a restart
    preserved_transcript: bool,
    preserved_fixed_pitch: bool,

    debug_verbosity: DebugVerbosity,
    error_mode: ErrorMode,
}

struct PropertyData {
    size: usize,
    property_number: usize,
    property_data_address: usize,
    next_property_address: usize,
}

enum TextParseState {
    Normal,
    Abbrev,
    ExtendedChar1,
    ExtendedChar2,
}

impl<'a> MemoryReader for VM {
    // Return the byte at address, with error if read is outside of bounds
    fn get_byte(&self, address: usize) -> Result<u8, ZmachineError> {
        if address > self.memory.len() {
            self.debug(format!(
                "get_byte(): attempt to read word at {} when length is {}",
                address,
                self.memory.len()
            ));
            return Err(ZmachineError::MemoryOutOfBoundsRead(address));
        }

        Ok(self.memory[address])
    }

    /// Return the byte at address, or error if addresss outside of interpreter writeable bounds
    fn get_byte_bounds_check(&self, address: usize) -> Result<u8, ZmachineError> {
        if !self.is_readable(address) {
            Err(ZmachineError::MemoryOutOfBoundsRead(address))
        } else {
            self.get_byte(address)
        }
    }

    /// Return a vector of length bytes starting at address
    fn get_bytes(&self, address: usize, length: usize) -> Result<Vec<u8>, ZmachineError> {
        let mut bytes = Vec::new();

        for i in 0..length {
            bytes.push(self.get_byte(address + i)?);
        }

        Ok(bytes)
    }

    // Return the specified bit at the address. Bit 0 is the rightmost (least significant)
    fn get_bit(&self, address: usize, bit: u8) -> Result<bool, ZmachineError> {
        if address > self.memory.len() {
            self.debug(format!(
                "get_bit(): attempt to read bit at {} when length is {}",
                address,
                self.memory.len()
            ));
            return Err(ZmachineError::MemoryOutOfBoundsRead(address));
        }

        if bit > 7 {
            self.debug(format!(
                "get_bit(): attempt to read invalid bit {} at address {}",
                bit, address
            ));
            return Err(ZmachineError::MemoryInvalidBit(address, bit));
        }

        Ok((self.memory[address] >> bit) & 0x01 == 1)
    }

    // Return the word at address, with error if read is outside of bounds
    fn get_word(&self, address: usize) -> Result<u16, ZmachineError> {
        if address + 1 > self.memory.len() {
            self.debug(format!(
                "get_word(): attempt to read word at {} when length is {}",
                address,
                self.memory.len()
            ));
            return Err(ZmachineError::MemoryOutOfBoundsRead(address));
        }

        Ok((self.memory[address] as u16) << 8 | (self.memory[address + 1] as u16))
    }

    /// Return the word at address, or error if addresss outside of interpreter writeable bounds
    fn get_word_bounds_check(&self, address: usize) -> Result<u16, ZmachineError> {
        if !self.is_readable(address) {
            Err(ZmachineError::MemoryOutOfBoundsRead(address))
        } else {
            self.get_word(address)
        }
    }

    // Per 1.2.3, packed addreses are used for routines/strings. Varies based on version
    fn convert_packed_address(&self, address: u16) -> usize {
        match self.version {
            ZCodeVersion::V1 => (address as usize) * 2,
            ZCodeVersion::V2 => (address as usize) * 2,
            ZCodeVersion::V3 => (address as usize) * 2,
        }
    }

    /// Return the current stack pointer
    fn get_stack_pointer(&self) -> usize {
        self.stack.len()
    }

    /// Return the value for the provided variable. Pops stack if variable number is for stack.
    fn get_variable(&mut self, variable_number: u8) -> Result<u16, ZmachineError> {
        if variable_number == STACK_VARIABLE {
            match self.routine_stack.last_mut() {
                None => Err(ZmachineError::MemoryStackOverflowRoutine()),
                Some(routine) => {
                    if routine.stack_pointer < self.stack.len() {
                        match self.stack.pop() {
                            None => Err(ZmachineError::MemoryStackOverflowGame()),
                            Some(num) => Ok(num),
                        }
                    } else {
                        Err(ZmachineError::MemoryStackOverflowRoutine())
                    }
                }
            }
        } else {
            self.peek_variable(variable_number, false)
        }
    }

    /// Return the value for the provided variable. Does not pop stack.
    fn peek_variable(
        &self,
        variable_number: u8,
        ignore_locals: bool,
    ) -> Result<u16, ZmachineError> {
        if ignore_locals && variable_number > 0 && variable_number < MAX_LOCAL_VAR {
            Ok(0)
        } else if variable_number == STACK_VARIABLE {
            match self.stack.last() {
                None => Err(ZmachineError::MemoryStackOverflowGame()),
                Some(num) => Ok(*num),
            }
        } else if variable_number <= MAX_LOCAL_VAR {
            match self.routine_stack.last() {
                None => Err(ZmachineError::MemoryStackOverflowRoutine()),
                Some(routine) => {
                    if (variable_number - 1) as usize >= routine.local_variables.len() {
                        println!(
                            "Request to peek variable {} when local vars length is {}",
                            variable_number,
                            routine.local_variables.len()
                        );

                        return Err(ZmachineError::MemoryInvalidLocalVariable(variable_number));
                    }

                    Ok(routine.local_variables[(variable_number - 1) as usize])
                }
            }
        } else {
            let offset: usize =
                (variable_number as usize - MAX_LOCAL_VAR as usize - 1) * WORD_LENGTH;
            Ok(self.get_word(self.global_variable_address as usize + offset)?)
        }
    }
    fn verify_checksum(&self, _: u16) -> std::result::Result<bool, ZmachineError> {
        Ok(true)
    }
}

impl<'a> ObjectTreeReader for VM {
    // Return the address of the property data for the numbered property, or 0 if no such property
    fn get_property_address(&self, object: usize, property: usize) -> Result<usize, ZmachineError> {
        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                if property > 31 {
                    self.debug(format!(
                        "get_property_address: out of range property {} on object {}",
                        property, object
                    ));

                    return Err(ZmachineError::ObjectInvalidProperty(property));
                }
                let mut properties_addr = self.get_properties_address(object)?;

                // Start of properties will be one byte of text length, followed by
                // that many words of text
                let short_name_len = self.get_byte(properties_addr)?;
                properties_addr = properties_addr + 1 + (short_name_len as usize * 2);

                loop {
                    match self.property_at_address(properties_addr) {
                        Err(err) => {
                            return Err(err);
                        }
                        Ok(data) => {
                            if data.property_number == 0 {
                                break;
                            }

                            if data.property_number == property {
                                return Ok(data.property_data_address);
                            }

                            properties_addr = data.next_property_address;
                        }
                    }
                }

                Ok(0)
            }
        }
    }

    // Return the short name (as unicode) for object number `object`. Return "Nothing" for 0.
    fn get_short_name(&mut self, object: usize) -> Result<String, ZmachineError> {
        if object == OBJECT_NOTHING {
            // Object 0 does not exist, it's "nothing"
            return Ok(String::from("Nothing"));
        }

        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                // Start of properties will be one byte of text length, followed by
                // that many words of text
                let properties_addr = self.get_properties_address(object)?;
                let short_name_len = self.get_byte(properties_addr)?;
                if short_name_len == 0 {
                    return Ok(String::new());
                }
                match self.text_to_utf(properties_addr + 1, short_name_len as usize, false) {
                    Err(msg) => {
                        self.debug(format!(
                            "Error parsing short name for object {}: {:?}",
                            object, msg
                        ));
                        Ok(String::from("Error parsing object name"))
                    }
                    Ok(text) => Ok(text),
                }
            }
        }
    }

    // Return the next property number after `property` for object `object`. If 0, first property. Next/first
    // is in the ordered list provided, which starts with highest property number first. Returns 0 when last prop found
    fn get_next_property(&self, object: usize, property: usize) -> Result<usize, ZmachineError> {
        if object == OBJECT_NOTHING {
            return Err(ZmachineError::ObjectInvalid(object));
        }

        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                if property > MAX_PROPERTY_123 {
                    self.debug(format!("get_next_property: request to read out of bounds property # {} for object {}",property,object));
                    return Err(ZmachineError::ObjectInvalidProperty(property));
                }

                let mut property_number: usize;
                let mut properties_addr: usize = self.get_properties_address(object)?;

                // Start of properties will be one byte of text length, followed by
                // that many words of text
                let short_name_len = self.get_byte(properties_addr)?;
                properties_addr = properties_addr + 1 + (short_name_len as usize * 2);

                loop {
                    match self.property_at_address(properties_addr) {
                        Err(err) => {
                            return Err(err);
                        }
                        Ok(data) => {
                            property_number = data.property_number;
                            if property_number < property || property == 0 {
                                break;
                            }

                            properties_addr = data.next_property_address;
                        }
                    }
                }

                Ok(property_number)
            }
        }
    }

    // Return the property # `property` for object `object`, or default if property does not exist
    // Property will be anywhere from 1-8 bytes, returned as the count and first byte
    fn get_property(&self, object: usize, property: usize) -> Result<Property, ZmachineError> {
        if object == OBJECT_NOTHING {
            return Err(ZmachineError::ObjectInvalid(property));
        }

        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                if property == 0 || property > MAX_PROPERTY_123 {
                    self.debug(format!(
                        "get_property: request to read out of bounds property # {} for object {}",
                        property, object
                    ));

                    return Err(ZmachineError::ObjectInvalidProperty(property));
                }

                let mut properties_addr: usize = self.get_properties_address(object)?;

                // Start of properties will be one byte of text length, followed by
                // that many words of text
                let short_name_len = self.get_byte(properties_addr)?;
                properties_addr = properties_addr + 1 + (short_name_len as usize * 2);

                loop {
                    match self.property_at_address(properties_addr) {
                        Err(err) => {
                            return Err(err);
                        }
                        Ok(data) => {
                            if data.property_number == 0 {
                                break;
                            }

                            if data.property_number == property {
                                let mut value = 0;

                                // Extract property value
                                for i in 0..data.size {
                                    let v = (self.get_byte(data.property_data_address + i)?
                                        as usize)
                                        << (8 * (data.size - 1 - i));
                                    value += v;
                                }

                                return Ok(Property {
                                    object,
                                    property,
                                    value,
                                    size: data.size,
                                    start_address: data.property_data_address,
                                });
                            }

                            properties_addr = data.next_property_address;
                        }
                    }
                }

                match self.get_default_property(property) {
                    Err(err) => Err(err),
                    Ok(value) => Ok(Property {
                        object,
                        property,
                        size: 0,
                        start_address: 0,
                        value: value as usize,
                    }),
                }
            }
        }
    }

    // Return parent for for object number `object`. 0 is no parent.
    fn get_parent(&self, object: usize) -> Result<usize, ZmachineError> {
        if object == OBJECT_NOTHING {
            // Object 0 does not exist, it's "nothing"
            return Ok(OBJECT_NOTHING);
        }

        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                match self.calculate_object_address(object) {
                    Err(msg) => Err(msg),
                    Ok(addr) => match self.get_byte(addr + OBJECT_TABLE_PARENT_OFFSET) {
                        Err(msg) => Err(msg),
                        Ok(parent_object) => Ok(parent_object as usize),
                    },
                }
            }
        }
    }

    // Return child for for object number `object`. 0 is no child.
    fn get_child(&self, object: usize) -> Result<usize, ZmachineError> {
        if object == OBJECT_NOTHING {
            // Object 0 does not exist, it's "nothing"
            return Ok(OBJECT_NOTHING);
        }

        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                match self.calculate_object_address(object) {
                    Err(msg) => Err(msg),
                    Ok(addr) => match self.get_byte(addr + OBJECT_TABLE_CHILD_OFFSET) {
                        Err(msg) => Err(msg),
                        Ok(child_object) => Ok(child_object as usize),
                    },
                }
            }
        }
    }

    // Return sibling for for object number `object`. 0 is no sibling.
    fn get_sibling(&self, object: usize) -> Result<usize, ZmachineError> {
        if object == OBJECT_NOTHING {
            // Object 0 does not exist, it's "nothing"
            return Ok(OBJECT_NOTHING);
        }

        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                match self.calculate_object_address(object) {
                    Err(msg) => Err(msg),
                    Ok(addr) => match self.get_byte(addr + OBJECT_TABLE_SIBLING_OFFSET) {
                        Err(msg) => Err(msg),
                        Ok(sibling_object) => Ok(sibling_object as usize),
                    },
                }
            }
        }
    }

    // Return attribute number `attribute` for object number `object`
    fn get_attribute(&self, object: usize, attribute: u8) -> Result<bool, ZmachineError> {
        if object == 0 {
            // Object 0 does not exist, it's "nothing"
            return Ok(false);
        }

        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                match self.calculate_object_address(object) {
                    Err(msg) => Err(msg),
                    Ok(addr) => {
                        // 12.3.1 - 4 bytes of attributes, with bit 7 of byte 0 being attr 0, and bit 0 of byte 3 being 31
                        match attribute {
                            0..=7 => Ok(self.get_bit(addr, 7 - attribute)?),
                            8..=15 => Ok(self.get_bit(addr + 1, 15 - attribute)?),
                            16..=23 => Ok(self.get_bit(addr + 2, 23 - attribute)?),
                            24..=31 => Ok(self.get_bit(addr + 3, 31 - attribute)?),
                            _ => {
                                self.debug(format!(
                                    "get_attribute: out of bounds attribute {} for object {}",
                                    attribute, object
                                ));
                                Err(ZmachineError::OutOfBoundsAttribute(attribute))
                            }
                        }
                    }
                }
            }
        }
    }

    /// Get the length of the property at the property address. Note the property size is one (or two,based on version)
    /// bytes back from the property address itself.
    fn get_property_length(
        &self,
        property_address: usize,
    ) -> std::result::Result<usize, ZmachineError> {
        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                let prop_len = self
                    .property_at_address(property_address - BYTE_LENGTH)?
                    .size;
                Ok(prop_len)
            }
        }
    }
}

impl VM {
    pub fn create_empty() -> VM {
        VM {
            version: ZCodeVersion::V1,
            story: Vec::new(),
            memory: Vec::new(),
            routine_stack: Vec::new(),
            stack: Vec::new(),
            error_mode: ErrorMode::Panic,
            high_memory_address: 0,
            initial_pc_address: 0,
            dictionary_address: 0,
            object_table_address: 0,
            object_tree_address: 0,
            global_variable_address: 0,
            static_memory_address: 0,
            abbrev_table_address: 0,
            status_mode: StatusMode::Score,
            file_length: 0,
            checksum: 0,
            release_number: 0,
            serial: String::new(),
            serial_raw: [0, 0, 0, 0, 0, 0],
            inform_version: String::new(),
            text_mapper: Box::new(ZCharacterMapperStub::create()),
            state: VMState::Initializing,
            pc: 0,
            dictionary_words: Vec::new(),
            dictionary_entry_length: 0,
            dictionary_word_separators: Vec::new(),
            memory_stream_stack: Vec::new(),
            debug_verbosity: DebugVerbosity::None,
            rng: Box::new(RandomModeRNG {}),
            preserved_transcript: false,
            preserved_fixed_pitch: false,
        }
    }

    // Initialize the story
    pub fn create_from_story_bytes(
        story_data: Vec<u8>,
        validate_checksum: bool,
        check_length: bool,
    ) -> Result<VM, VMLoadError> {
        // Validate minimum size
        if story_data.len() < MINIMUM_SIZE {
            return Err(VMLoadError::StoryFileTooSmall(story_data.len()));
        }

        let mut vm = VM::create_empty();

        match vm.load_story_data(story_data, validate_checksum, check_length) {
            Err(e) => Err(e),
            Ok(()) => Ok(vm),
        }
    }

    pub fn load_story_data(
        &mut self,
        story_data: Vec<u8>,
        validate_checksum: bool,
        check_length: bool,
    ) -> Result<(), VMLoadError> {
        // Validate version
        self.story = story_data.clone();
        self.memory = story_data.clone();

        let version = match story_data[HEADER_VERSION] {
            1 => ZCodeVersion::V1,
            2 => ZCodeVersion::V2,
            3 => ZCodeVersion::V3,
            _ => return Err(VMLoadError::UnsupportedVersion()),
        };

        self.version = version;
        self.text_mapper = match version {
            ZCodeVersion::V1 => Box::new(ZCharacterMapperStub::create()),
            ZCodeVersion::V2 => Box::new(ZCharacterMapperV2::create()),
            ZCodeVersion::V3 => Box::new(ZCharacterMapperV3::create()),
        };

        // See 1.1.4
        match version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                if story_data.len() > MAX_LENGTH_V1TO3 {
                    self.debug(format!(
                        "Expected max length of story of {}, got {}",
                        MAX_LENGTH_V1TO3,
                        story_data.len()
                    ));
                    return Err(VMLoadError::StoryFileTooLarge(story_data.len()));
                }
            }
        }

        // Handles all initialization that might throw a ZMachineError
        if let Err(zme) = self.initialize(version) {
            return Err(VMLoadError::InterpreterError(format!("{:?}", zme)));
        }

        // Validate checksum and file length. They can both be 0, in which case they can be ignored
        if self.checksum > 0 && validate_checksum {
            let mut checksum_counter: u32 = 0;
            // Checksum is calculated post-header
            for byte in story_data[0x40..].iter() {
                checksum_counter += (*byte) as u32;
            }

            let checksum: u16 = (checksum_counter % 0xffff_u32) as u16;

            if checksum != self.checksum {
                self.debug(format!(
                    "Expected checksum {:04X}, actual checksum {:04X}",
                    self.checksum, checksum
                ));
                return Err(VMLoadError::ChecksumMismatch());
            }
        }

        if check_length && self.file_length > 0 && self.file_length != story_data.len() {
            self.debug(format!(
                "Expected length {}, actual length {}",
                self.file_length,
                story_data.len()
            ));
            return Err(VMLoadError::LengthMismatch());
        }

        // Switch to running
        self.state = VMState::Running;

        Ok(())
    }

    fn initialize(&mut self, version: ZCodeVersion) -> Result<(), ZmachineError> {
        // Set initial values. They will all be in bounds
        self.high_memory_address = self.get_word(HEADER_HIGHMEM_ADDRESS)?;
        self.initial_pc_address = self.get_word(HEADER_PC_ADDRESS)?;
        self.dictionary_address = self.get_word(HEADER_DICTIONARY_ADDRESS)?;
        self.global_variable_address = self.get_word(HEADER_GLOBALS_ADDRESS)?;
        self.static_memory_address = self.get_word(HEADER_STATIC_ADDRESS)?;
        self.abbrev_table_address = self.get_word(HEADER_ABBREVS_ADDRESS)?;
        self.object_table_address = self.get_word(HEADER_OBJECT_ADDRESS)?;

        // See 12.2
        match version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                // 31 words of object table
                self.object_tree_address =
                    self.object_table_address + (MAX_PROPERTY_123 * 2) as u16;
            }
        }

        self.checksum = self.get_word(HEADER_CHECKSUM)?;

        if self.get_bit(HEADER_FLAGS_1, HEADER_STATUS_BIT)? {
            self.status_mode = StatusMode::Time;
        }

        self.release_number = self.get_word(HEADER_RELEASE_NUMBER)?;
        for i in 0..6 {
            self.serial_raw[i] = self.get_byte(HEADER_SERIAL + i)?;
            self.serial.push(self.get_byte(HEADER_SERIAL + i)? as char);
        }

        for i in 0..4 {
            self.inform_version
                .push(self.get_byte(HEADER_INFORM_VERSION + i)? as char);
        }

        // See 11.1.6
        match version {
            ZCodeVersion::V1 => {
                self.file_length =
                    self.get_word(HEADER_FILE_LENGTH)? as usize * V123_FILE_LENGTH_MULTIPLIER;
            }
            ZCodeVersion::V2 => {
                self.file_length =
                    self.get_word(HEADER_FILE_LENGTH)? as usize * V123_FILE_LENGTH_MULTIPLIER;
            }
            ZCodeVersion::V3 => {
                self.file_length =
                    self.get_word(HEADER_FILE_LENGTH)? as usize * V123_FILE_LENGTH_MULTIPLIER;
            }
        };

        self.load_dictionary()?;

        // Restart is designed to preserve two flags, so these are
        // temporarily stored
        self.preserve_restart_restore_flags()?;

        // Initialize game
        self.restart_game()?;

        // Reset memory like a restart/restore
        self.reset_header()?;

        Ok(())
    }
    pub fn refresh_status(&mut self, io: &mut dyn TerpIO) {
        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                let obj_num = self.get_variable(GLOBAL_1).expect("Couldn't get global 1") as usize;
                let score = self.get_variable(GLOBAL_2).expect("Couldn't get global 2") as usize;
                let turns = self.get_variable(GLOBAL_3).expect("Couldn't get global 3") as usize;
                let room_name = match obj_num {
                    0..=MAX_OBJECT_V3 => self
                        .get_short_name(obj_num)
                        .expect("Error getting shortname"),
                    _ => String::from("INVALID ROOM"),
                };
                match self.status_mode {
                    StatusMode::Score => {
                        let signed_score = word_to_signed(score as u16);
                        io.draw_status(
                            room_name.as_str(),
                            (format!("{}/{}", signed_score, turns)).as_str(),
                        );
                    }
                    StatusMode::Time => {
                        io.draw_status(
                            room_name.as_str(),
                            (format!("{:02}:{:02}", score, turns)).as_str(),
                        );
                    }
                }
            }
        }
    }

    fn print_to_output(&mut self, text: &str, io: &mut dyn TerpIO) {
        if self.memory_stream_stack.is_empty() {
            if io.is_screen_output_active() {
                io.print_to_screen(text);
            }

            if io.is_transcript_active() {
                io.print_to_transcript(text);
            }
        } else if let Some(len_addr) = self.memory_stream_stack.last() {
            let len_addr = *len_addr as usize;
            if let Err(err) = self.print_to_memory(len_addr, text) {
                println!("Error printing to memory. {:?}", err);
            }
        }
    }

    fn print_to_memory(&mut self, len_addr: usize, text: &str) -> Result<(), ZmachineError> {
        // Print to a table in memory. First word contains the total number of bytes, bytes start after this word
        let mut offset = self.get_word(len_addr)? as usize;
        let addr = len_addr + WORD_LENGTH;
        for c in text.as_bytes().iter() {
            self.set_byte(
                addr + offset,
                match *c {
                    // This match handles 7.1.2.2.1 -- newlines become carriage return for memory
                    10 => 13,
                    _ => *c,
                },
            )?;
            offset += BYTE_LENGTH;
            if offset == MAX_WORD_LENGTH {
                return Err(ZmachineError::TableWriteOverflow());
            }
        }
        self.set_word(len_addr, offset as u16)?;

        Ok(())
    }

    ///
    /// Take an action and mutate the VM accordingly
    ///
    pub fn handle_action(&mut self, action: Action, io: &mut dyn TerpIO) {
        match action {
            Action::Nop(addr) => {
                // Do nothing. Used in invert_action
                self.pc = addr;
            }
            Action::Restart() => {
                self.debug(String::from("          RESTART"));
                if let Err(msg) = self.restart_story() {
                    self.print_to_output(format!("ERROR RESTARTING: {:?}", msg).as_str(), io);
                }
            }
            Action::Restore(addr, invert, branch_addr) => {
                self.debug(format!(
                    "          RESTORE PC {:04X} invert: {} branch: {:04X}",
                    addr, invert, branch_addr
                ));
                self.state = VMState::RestorePrompt;
                // Set PC assuming failure
                if invert {
                    self.pc = branch_addr;
                } else {
                    self.pc = addr;
                }
            }
            Action::Save(addr, invert, branch_addr) => {
                self.debug(format!(
                    "          SAVE PC {:04X} invert: {} branch: {:04X}",
                    addr, invert, branch_addr
                ));

                // Set the PC so restore ends up where story will be
                // post-save

                if invert {
                    self.pc = addr;
                    self.state = VMState::SavePrompt(addr, branch_addr);
                } else {
                    self.pc = branch_addr;
                    self.state = VMState::SavePrompt(branch_addr, addr);
                }
            }
            Action::SoundEffect(sound, effect, volume, addr) => {
                self.debug(format!("          SOUND EFFECT PC {:04X}", addr));
                io.play_sound_effect(sound, effect, volume);
                self.pc = addr;
            }
            Action::SplitWindow(lines, addr) => {
                self.debug(format!(
                    "          SPLIT WINDOW with {} lines, PC {:04X}",
                    lines, addr
                ));
                io.split_window(lines as usize);
                self.pc = addr;
            }
            Action::SetWindow(window_number, addr) => {
                self.debug(format!(
                    "          SET WINDOW to window {:?}, PC {:04X}",
                    window_number, addr
                ));
                io.set_window(window_number);
                self.pc = addr;
            }
            Action::SwitchInputStream(input_stream, addr) => {
                self.debug(format!(
                    "          SWITCH INPUT STREAM TO to {:?}, PC {:04X}",
                    input_stream, addr
                ));
                match input_stream {
                    InputStreamEnum::Keyboard => {
                        io.set_command_input(false);
                    }
                    InputStreamEnum::File => {
                        if !io.supports_commands_input() {
                            self.print_to_output("INTERPRETER ERROR: cannot select input command stream as it is not configured \n", io);
                        } else {
                            io.set_command_input(true);
                        }
                    }
                };

                self.pc = addr;
            }
            Action::SetOutputStream(output_stream, table_addr, status, addr) => {
                self.debug(format!(
                    "          TOGGLE OUTPUT STREAM {:?} to {}, PC {:04X}",
                    output_stream, status, addr
                ));
                match output_stream {
                    OutputStreamEnum::Screen => {
                        io.set_screen_output(status);
                    }
                    OutputStreamEnum::Transcript => {
                        if status && !io.is_transcript_active() {
                            if io.supports_transcript() {
                                self.state = VMState::TranscriptPrompt;
                            } else {
                                self.print_to_output("INTERPRETER ERROR: cannot select transcrpt stream as it is not configured \n", io);
                            }
                        } else {
                            io.set_transcript(false);
                        }
                    }
                    OutputStreamEnum::Commands => {
                        if status {
                            if io.supports_commands_output() {
                                self.state = VMState::CommandOutputPrompt;
                            } else {
                                self.print_to_output("INTERPRETER ERROR: cannot select output command stream as it is not configured \n", io);
                            }
                        } else {
                            io.set_command_output(false);
                        }
                    }
                    OutputStreamEnum::Memory => {
                        if status {
                            match table_addr {
                                Some(table_addr) => {
                                    self.memory_stream_stack.push(table_addr);
                                    // Initialize the table length to 0
                                    if let Err(err) = self.set_word(table_addr as usize, 0) {
                                        self.set_error_state(format!(
                                            "Error initializing memory stream: {:?}",
                                            err
                                        ));
                                    }
                                }
                                None => self.set_error_state(
                                    "Request to open memory stream with no address.".to_string(),
                                ),
                            };

                            if self.memory_stream_stack.len() > MAX_MEMORY_STREAM_SIZE {
                                self.set_error_state(
                                    "Request to open memory stream when already at max."
                                        .to_string(),
                                );
                            }
                        } else if !self.memory_stream_stack.is_empty() {
                            // Spec doesn't say to throw error if unselect when no more streams, so let those
                            // occur without error
                            self.memory_stream_stack.pop();
                        }
                    }
                };
                self.pc = addr;
            }
            Action::ShowStatus(addr) => {
                self.debug(format!("          SHOW_STATUS PC {:04X}", addr));
                self.refresh_status(io);
                self.pc = addr;
            }
            Action::ReseedRNGAndStore(new_seed, store_var, new_pc) => {
                if new_seed != 0 {
                    self.reseed_rng_predicable(new_seed);
                } else {
                    self.reseed_rng();
                }
                match self.set_variable(store_var, 0) {
                    Err(msg) => {
                        self.set_error_state(format!("Error reseeding rng. {:?}", msg));
                    }
                    Ok(_uc) => {
                        self.pc = new_pc;
                    }
                }
            }
            Action::RandomAndStore(max_value, store_var, new_pc) => {
                let v = self.random_int(max_value);
                match self.set_variable(store_var, v) {
                    Err(msg) => {
                        self.set_error_state(format!("Error randomizing rng. {:?}", msg));
                    }
                    Ok(_uc) => {
                        self.pc = new_pc;
                    }
                }
            }
            Action::Jump(addr) => {
                self.debug(format!("          JUMP to {:04X}", addr));
                self.pc = addr;
            }
            Action::ReadLine(charcount, text_addr, parse_addr, pc_addr) => {
                self.debug(format!(
                    "          {} chars, text {:04X}, parse {:04X}",
                    charcount, text_addr, parse_addr
                ));
                self.set_state(VMState::WaitingForInput(pc_addr, text_addr, parse_addr));
                self.refresh_status(io);
                io.wait_for_line(charcount as usize);
            }
            Action::Quit() => {
                self.debug("          QUIT".to_string());
                self.set_state(VMState::Quit);
            }
            Action::Call(routine_addr, arg_count, l1, l2, l3, store_var, return_to) => {
                self.debug(format!(
                    "          CALL {:06X} operands {} {} {} ({}) st: {} rt: {}",
                    routine_addr, l1, l2, l3, arg_count, store_var, return_to
                ));
                self.debug(format!("Pre-call state : {}", self.get_state_string()));

                // Routine 0 is a special case -- just immediately return 0
                // see 6.4.3
                if routine_addr == 0 {
                    let _ = self.set_variable(store_var, ZMACHINE_FALSE);
                    self.pc = return_to;
                } else {
                    let arguments: Vec<u16> = match arg_count {
                        0 => {
                            vec![]
                        }
                        1 => {
                            vec![l1]
                        }
                        2 => {
                            vec![l1, l2]
                        }
                        _ => {
                            vec![l1, l2, l3]
                        }
                    };

                    let routine = Routine::create_from_address(
                        routine_addr as usize,
                        return_to,
                        arguments,
                        store_var,
                        self,
                        self.version,
                    )
                    .expect("Unable to create routine.");

                    // Move execution to the start of the routine
                    self.pc = routine.code_address;

                    self.routine_stack.push(routine);
                }

                self.debug(format!("Post-call state: {}", self.get_state_string()));
            }
            Action::Return(return_val) => {
                self.debug(format!("          RETURN with {:06X}", return_val));

                let routine = self
                    .routine_stack
                    .pop()
                    .expect("Returned from main routine.");

                if self.routine_stack.is_empty() {
                    panic!("Returned from main routine.");
                }

                // Clear anything added to stack -- 6.3.2
                let count = self.stack.len() - routine.stack_pointer;
                if count > 0 {
                    for _i in 0..count {
                        let _ = self.stack.pop();
                    }
                }

                // Set the variable to the return value
                let _ = self.set_variable(routine.store_var, return_val);
                // Move execution to after the original call
                self.pc = routine.return_to;
            }
            Action::PrintAddress(str_addr, pc_address, ret_true, print_nl) => {
                let result = self
                    .text_to_utf_and_addr(str_addr, 0, false)
                    .expect("Error retrieving string");
                self.debug(format!(
                    "          PRINT with addr {:06X}: \"{}\"",
                    str_addr, result.string
                ));

                self.print_to_output(result.string.as_str(), io);
                if print_nl {
                    self.print_to_output("\n", io);
                }

                if ret_true {
                    self.handle_action(Action::Return(ZMACHINE_TRUE), io);
                } else {
                    self.pc = match pc_address {
                        0 => result.address,
                        _ => pc_address,
                    };
                }
            }
            Action::PrintString(s, new_pc) => {
                self.debug(format!("          PRINT with str '{}'", s));

                self.print_to_output(s.as_str(), io);

                self.pc = new_pc;
            }
            Action::PrintChar(zc, new_pc) => {
                self.debug(format!("          PRINT_CHAR with zscii '{}'", zc));

                match self.zscii_to_output_char(zc) {
                    Err(msg) => {
                        // Don't hard stop on a bad character -- log and print a ?
                        self.error(format!("Error mapping zscii. {:?}", msg));
                        self.print_to_output("?", io);
                    }
                    Ok(uc) => {
                        self.print_to_output(format!("{}", uc).as_str(), io);
                    }
                }
                self.pc = new_pc;
            }
            Action::Pop(next_addr) => {
                self.debug(format!(
                    "          POP stack, next address {:06X}",
                    next_addr
                ));

                let _ = self.get_variable(0);
                self.pc = next_addr;
            }
            Action::PopAndStore(variable_number, next_addr) => {
                self.debug(format!(
                    "          PULL stack to variable 0x{:02X}, next address {:06X}",
                    variable_number, next_addr
                ));
                match self.get_variable(0) {
                    Err(msg) => {
                        self.set_error_state(format!("Error getting stack Var. {:?}", msg));
                    }
                    Ok(value) => match self.set_variable(variable_number, value) {
                        Err(msg) => {
                            self.set_error_state(format!(
                                "Error storing word {:04X} to variable 0x{:02X}: {:?}",
                                value, variable_number, msg
                            ));
                        }
                        Ok(_) => {
                            self.pc = next_addr;
                        }
                    },
                }
            }
            Action::SetProperty(object, property, val, next_addr) => {
                match self.set_property(object as usize, property as usize, val) {
                    Err(msg) => {
                        self.set_error_state(format!(
                            "Error setting object {} property {} to word {:04X}. {:?} ",
                            object, property, val, msg
                        ));
                    }
                    Ok(_) => {
                        self.pc = next_addr;
                    }
                }
            }
            Action::InsertObject(obj_num, destination, pc_addr) => {
                self.debug(format!(
                    "          INSERT OBJECT {:04X} under {:04X}, next address {:06X}",
                    obj_num, destination, pc_addr
                ));
                match self.insert_object(obj_num as usize, destination as usize) {
                    Err(msg) => {
                        self.set_error_state(format!("Error inserting object. {:?}", msg));
                    }
                    Ok(_value) => {
                        self.pc = pc_addr;
                    }
                }
            }
            Action::RemoveObject(obj_num, pc_addr) => {
                self.debug(format!(
                    "          REMOVE OBJECT {:04X}  next address {:06X}",
                    obj_num, pc_addr
                ));
                match self.remove_object(obj_num as usize) {
                    Err(msg) => {
                        self.set_error_state(format!("Error removing object. {:?}", msg));
                    }
                    Ok(_value) => {
                        self.pc = pc_addr;
                    }
                }
            }
            Action::StoreVariable(variable_number, value, next_addr, in_place) => {
                self.debug(format!(
                    "          STORE word {:04X} to variable 0x{:02X}, next address {:06X}",
                    value, variable_number, next_addr
                ));
                if in_place && variable_number == 0 && !self.stack.is_empty() {
                    // Pop stack before push so item is replaced
                    // UNLESS stack is empty -- then just push
                    if let Err(_msg) = self.get_variable(0) {
                        // self.set_error_state(format!(
                        //     "Error storing word {:04X} to variable 0x{:02X}: {}",
                        //     value, variable_number, msg
                        // ));
                        // return;
                    }
                }

                match self.set_variable(variable_number, value) {
                    Err(msg) => {
                        self.set_error_state(format!(
                            "Error storing word {:04X} to variable 0x{:02X}: {:?}",
                            value, variable_number, msg
                        ));
                    }
                    Ok(_) => {
                        self.pc = next_addr;
                    }
                }
            }
            Action::StoreVariableAndReturn(variable_number, value, return_val) => {
                self.debug(format!(
                    "          STORE word {:04X} to variable 0x{:02X}, return value {:04X}",
                    value, variable_number, return_val
                ));

                match self.set_variable(variable_number, value) {
                    Err(msg) => {
                        self.set_error_state(format!(
                            "Error storing word {:04X} to variable 0x{:02X}: {:?}",
                            value, variable_number, msg
                        ));
                    }
                    Ok(_) => {
                        let routine = self
                            .routine_stack
                            .pop()
                            .expect("Returned from main routine.");

                        if self.routine_stack.is_empty() {
                            panic!("Returned from main routine.");
                        }
                        // Set the variable to the return value
                        let _ = self.set_variable(routine.store_var, return_val);

                        // Move execution to after the original call
                        self.pc = routine.return_to;
                    }
                }
            }
            Action::StoreByte(addr, value, next_addr) => {
                self.debug(format!(
                    "          STORE byte {:02X} to addr {:06X}",
                    value, addr
                ));

                if !self.is_writeable(addr as usize) {
                    self.set_error_state(format!(
                        "StoreByte: attempt to use unwriteable address {:06X}",
                        addr
                    ));
                } else {
                    match self.set_byte(addr, value) {
                        Err(msg) => {
                            self.set_error_state(format!(
                                "Error storing byte {:02X} at addr {:06X}: {:?}",
                                value, addr, msg
                            ));
                        }
                        Ok(_) => {
                            self.pc = next_addr;
                        }
                    }
                }
            }
            Action::StoreBytes(addr, bytes, next_addr) => {
                self.debug(format!(
                    "          STORE bytes {:?} to addr {:06X}",
                    bytes, addr
                ));

                if !self.is_writeable_range(addr as usize, bytes.len()) {
                    self.set_error_state(format!(
                        "StoreBytes: attempt to use unwriteable address {:06X} w/ length {:}",
                        addr,
                        bytes.len()
                    ));
                } else {
                    match self.set_bytes(addr, bytes) {
                        Err(msg) => {
                            self.set_error_state(format!(
                                "Error storing bytes to addr {:06X}: {:?}",
                                addr, msg
                            ));
                        }
                        Ok(_) => {
                            self.pc = next_addr;
                        }
                    }
                }
            }
            Action::StoreWord(addr, value, next_addr) => {
                self.debug(format!(
                    "          STORE word {:04X} to addr {:06X}",
                    value, addr
                ));
                if !self.is_writeable_range(addr as usize, WORD_LENGTH) {
                    self.set_error_state(format!(
                        "StoreWord: attempt to use unwriteable address {:06X}",
                        addr
                    ));
                } else {
                    match self.set_word(addr, value) {
                        Err(msg) => {
                            self.set_error_state(format!(
                                "Error storing word {:04X} at addr {:06X}: {:?}",
                                value, addr, msg
                            ));
                        }
                        Ok(_) => {
                            self.pc = next_addr;
                        }
                    }
                }
            }
            Action::SetAttr(obj_number, attr_number, val, pc) => {
                match self.set_attribute(obj_number, attr_number, val) {
                    Err(msg) => {
                        self.state = VMState::Error;
                        self.set_error_state(format!(
                            "Error in SetAttr setting obj {} attrr {} to {}: {:?}",
                            obj_number, attr_number, val, msg
                        ));
                    }
                    Ok(_) => {
                        // Move execution to the start of the routine
                        self.pc = pc;
                    }
                }
            }
        }
    }
    ///

    ///  Execute the current instruction and move the PC to the next stateF(M ())
    ///
    pub fn tick(&mut self, io: &mut dyn TerpIO) {
        match self.state {
            VMState::WaitingForInput(pc_addr, text_addr, parse_addr) => {
                if !io.waiting_for_input() {
                    let last_input = io.last_input();
                    if io.is_transcript_active() {
                        // 7.1.1.1 -- echo text to transcript. Screen echo is handled by screen
                        io.print_to_transcript(last_input.as_str());
                        io.print_to_transcript("\n");
                    }
                    if io.is_command_output_active() {
                        io.print_to_commands(last_input.as_str());
                        io.print_to_commands("\n");
                    }
                    if io.is_reading_from_commands() {
                        self.print_to_output(last_input.as_str(), io);
                        self.print_to_output("\n", io);
                        io.recalculate_and_redraw(false);
                    }
                    match self.handle_input_text(last_input, text_addr, parse_addr) {
                        Err(msg) => {
                            self.set_error_state(format!(
                                "Error post handle_input_text: {:?}",
                                msg
                            ));
                        }
                        Ok(_) => {
                            self.pc = pc_addr;
                            self.set_state(VMState::Running);
                        }
                    }
                }
            }
            VMState::Running => {
                // Special case for 7.4 -- check transcript bit to see if it changed
                let process_instruction = match self.version {
                    ZCodeVersion::V3 => {
                        let transcript_bit = self
                            .get_bit(HEADER_FLAGS_2, 0)
                            .expect("Error checking header");
                        if transcript_bit != io.is_transcript_active() && io.supports_transcript() {
                            if transcript_bit {
                                self.handle_action(
                                    Action::SetOutputStream(
                                        OutputStreamEnum::Transcript,
                                        None,
                                        true,
                                        self.pc,
                                    ),
                                    io,
                                );
                                false
                            } else {
                                io.set_transcript(false);
                                true
                            }
                        } else {
                            true
                        }
                    }
                    ZCodeVersion::V1 | ZCodeVersion::V2 => (true),
                };
                if process_instruction {
                    match handle_instruction(self.pc, self, self.version, self.debug_verbosity) {
                        Err(msg) => {
                            self.set_error_state(format!("Error: {:?}", msg));
                        }
                        Ok((action, instruction)) => {
                            if let Some(msg) = instruction {
                                self.debug(format!("0x{:06X}: {:}", self.pc, msg));
                            }
                            self.handle_action(action, io);
                        }
                    }
                }
            }
            _ => {
                self.set_error_state("Tick called in non waiting/running state".to_string());
            }
        }
    }

    /// Generate a random number using the logic in section 2.4
    pub fn random_int(&mut self, max_value: u16) -> u16 {
        self.rng.next_value(max_value)
    }

    /// Reseed the RNG to a specific value.
    pub fn reseed_rng_predicable(&mut self, new_seed: u16) {
        self.rng = match new_seed {
            0..=1000 => Box::new(PredicatableRNG {
                sequence: 0,
                seed: new_seed,
            }),
            _ => Box::new(SeededRNG {
                rng: ChaCha20Rng::seed_from_u64(new_seed as u64),
            }),
        };
    }

    pub fn get_quetzal_data(&self, compressed: bool) -> QuetzalData {
        // Get the data needed to save a game
        let mut data = QuetzalData {
            release_number: self.release_number,
            serial: self.serial_raw,
            checksum: self.checksum,
            initial_pc: self.pc,
            stack_frames: vec![],
            data: vec![],
            data_is_compressed: compressed,
        };
        // Extract stack frames
        let routine_count = self.routine_stack.len();
        for i in 0..routine_count {
            let routine = &self.routine_stack[i];
            let mut frame = QueztalStackFrame {
                return_pc: routine.return_to,
                result_var: routine.store_var,
                flags: 0,
                arguments: 0,
                local_variables: routine.local_variables.clone(),
                evaluation_stack: vec![],
            };

            // See 4.3.2
            let flags: u8 = (routine.local_variables.len() & 0x0f) as u8;
            frame.flags = flags | if routine.discard { 0x10 } else { 0x00 };

            data.stack_frames.push(frame);
        }

        // Copy stack data
        let mut sp = 0;
        for r in 0..routine_count {
            let max_sp = if r == routine_count - 1 {
                self.stack.len()
            } else {
                self.routine_stack[r + 1].stack_pointer
            };

            while sp < max_sp {
                data.stack_frames[r].evaluation_stack.push(self.stack[sp]);
                sp += 1;
            }
        }

        if compressed {
            data.data = compress_story_data(
                self.static_memory_address as usize,
                &self.story,
                &self.memory,
            );
        } else {
            // If not compressed, just copy dynamic memory

            for (idx, b) in self.memory.iter().enumerate() {
                if idx >= self.static_memory_address as usize {
                    break;
                }
                data.data.push(*b);
            }
        }

        data
    }

    pub fn restore_game(&mut self, quetzal_data: QuetzalData) -> Result<bool, ZmachineError> {
        // Note that this restore will not meet requiement 8.6.1.3 (unsplit screen) as it has no access
        // to a screen object and might be be used before the screen is even active. This requirements must be
        // handled by the interpreter itself
        self.preserve_restart_restore_flags()?;
        if quetzal_data.release_number != self.release_number {
            return Err(ZmachineError::SaveReleaseNumberMismatch(
                quetzal_data.release_number,
                self.release_number,
            ));
        }

        if quetzal_data.serial != self.serial_raw {
            return Err(ZmachineError::SaveSerialNumberMismatch(quetzal_data.serial));
        }

        if quetzal_data.checksum != self.checksum {
            return Err(ZmachineError::SaveChecksumMismatch(
                self.checksum,
                quetzal_data.checksum,
            ));
        }

        // Convert the stored stack frames into routine structs
        self.debug("Loading routines/stack".to_string());

        self.routine_stack.clear();
        self.stack.clear();
        for (idx, frame) in quetzal_data.stack_frames.iter().enumerate() {
            self.debug(format!("Loading frame {}. {:?}", idx, frame));
            for word in &frame.evaluation_stack {
                self.stack.push(*word);
            }

            // 4.11.1 calls for a dummy stack frame -- that's something
            // that this terp already creates
            self.routine_stack.push(Routine::create_from_data(
                0,
                frame.return_pc,
                frame.local_variables.clone(),
                frame.result_var,
                self.stack.len(),
            ));
        }

        if !quetzal_data.data_is_compressed {
            self.debug("Loading memory -- uncompressed".to_string());

            if quetzal_data.data.len() != self.static_memory_address as usize {
                return Err(ZmachineError::SaveDataMemoryMismatch());
            }

            for (idx, byte) in quetzal_data.data.iter().enumerate() {
                self.memory[idx] = *byte;
            }
        } else {
            self.debug("Loading memory -- compressed".to_string());
            load_compressed_save_data(
                &quetzal_data.data,
                self.static_memory_address,
                &self.story,
                &mut self.memory,
            )?;
        }

        self.reset_header()
            .expect("Error resetting header after restore");

        // In a "normal" PC this has to be incremented by 1 for the game to properly restore.
        self.pc = quetzal_data.initial_pc + 1;
        Ok(true)
    }

    /// Reseed the RNG to a random value.
    pub fn reseed_rng(&mut self) {
        self.rng = Box::new(RandomModeRNG {});
    }

    /// Set the PC to a given address
    pub fn set_pc(&mut self, pc: usize) {
        self.pc = pc;
    }
    pub fn get_state(&self) -> VMState {
        self.state
    }

    /// Only public to assist with testing. Don't blindly mutate the state here.
    pub fn set_state(&mut self, state: VMState) {
        self.state = state;
    }

    fn set_error_state(&mut self, message: String) {
        self.set_state(VMState::Error);
        self.error(message);
    }

    pub fn get_pc(&self) -> usize {
        self.pc
    }

    /// Perform a full restart of the story, as if RESTART had been typed
    pub fn restart_story(&mut self) -> Result<bool, ZmachineError> {
        self.preserve_restart_restore_flags()
            .expect("Error preserving flags");
        self.memory.clear();
        for b in self.story.iter() {
            self.memory.push(*b);
        }
        if let Err(msg) = self.restart_game() {
            self.error(format!("{:?}", msg));
        } else if let Err(msg) = self.reset_header() {
            self.error(format!("{:?}", msg));
        } else {
            self.state = VMState::Running;
        }

        Ok(true)
    }

    fn restart_game(&mut self) -> Result<bool, ZmachineError> {
        self.routine_stack.clear();

        // Setup the initial routine. Note it has no local variables (5.5)
        self.routine_stack
            .push(Routine::create_empty(self.initial_pc_address as usize, 0));

        self.pc = self.initial_pc_address as usize;

        // See 2.4
        self.reseed_rng();

        Ok(true)
    }

    fn set_attribute(
        &mut self,
        object: u16,
        attribute: u8,
        val: bool,
    ) -> Result<bool, ZmachineError> {
        if object == 0 {
            // Object 0 does not exist, it's "nothing"
            return Ok(false);
        }

        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                match self.calculate_object_address(object as usize) {
                    Err(msg) => Err(msg),
                    Ok(addr) => {
                        // 12.3.1 - 4 bytes of attributes, with bit 7 of byte 0 being attr 0, and bit 0 of byte 3 being 31
                        match attribute {
                            0..=7 => Ok(self.set_bit(addr, 7 - attribute, val)?),
                            8..=15 => Ok(self.set_bit(addr + 1, 15 - attribute, val)?),
                            16..=23 => Ok(self.set_bit(addr + 2, 23 - attribute, val)?),
                            24..=31 => Ok(self.set_bit(addr + 3, 31 - attribute, val)?),
                            _ => {
                                self.debug(format!(
                                    "set_attribute: out of bounds attribute {} for object {}",
                                    attribute, object
                                ));
                                Err(ZmachineError::OutOfBoundsAttribute(attribute))
                            }
                        }
                    }
                }
            }
        }
    }

    /// See definition of restart/restore. Transcript and fixed pitch
    /// flags must be preserved
    fn preserve_restart_restore_flags(&mut self) -> Result<bool, ZmachineError> {
        self.preserved_transcript = self.get_bit(HEADER_FLAGS_2, 0)?;
        self.preserved_fixed_pitch = self.get_bit(HEADER_FLAGS_2, 1)?;

        Ok(true)
    }

    // Called at init or after restart/restore, sets flags and fields per spec
    fn reset_header(&mut self) -> Result<bool, ZmachineError> {
        self.set_bit(HEADER_FLAGS_1, HEADER_STATUS_NOT_AVAILABLE_BIT, false)?;
        self.set_bit(HEADER_FLAGS_1, HEADER_SCREEN_SPLIT_AVAILABLE_BIT, true)?;
        self.set_bit(HEADER_FLAGS_1, HEADER_VARIABLE_PITCH_BIT, false)?;

        // See 11.1.5. Note that the interpreterm meets the 1.1 spec
        self.set_word(HEADER_REVISION_NUMBER, 0x0101)?;

        // Per spec, preserve these flags
        self.set_bit(HEADER_FLAGS_2, 0, self.preserved_transcript)?;
        self.set_bit(HEADER_FLAGS_2, 1, self.preserved_fixed_pitch)?;
        Ok(true)
    }

    // Will log to console if debug mode on
    fn debug(&self, message: String) {
        match self.debug_verbosity {
            DebugVerbosity::None => {}
            DebugVerbosity::All => {
                println!("{}", message);
            }
        }
    }
    // Will always log to console
    fn error(&self, message: String) {
        println!("{}", message);
    }

    //
    // Address calculations and checks
    //

    // Can the game read from this address? See section 1
    pub fn is_readable(&self, address: usize) -> bool {
        address < cmp::min(self.get_last_address(), 0xffff)
    }

    // Can the game write to this address? See section 1
    pub fn is_writeable(&self, address: usize) -> bool {
        if address == HEADER_FLAGS_2 {
            return true;
        } else if address < HEADER_TOP {
            return false;
        }

        address < self.static_memory_address as usize
    }

    // Can the game write to any address in this range?
    pub fn is_writeable_range(&self, address: usize, range: usize) -> bool {
        if range < 2 {
            self.is_writeable(address)
        } else {
            self.is_writeable(address) && self.is_writeable(address + range - 1)
        }
    }

    // Per 1.2.2, word addresses are even addresses in lower 128K, stored as half the
    // address value. Used only for abbrevs
    pub fn convert_word_address(&self, address: u16) -> usize {
        (address * 2) as usize
    }

    //
    // Object table
    //
    pub fn calculate_object_address(&self, object: usize) -> Result<usize, ZmachineError> {
        if object == OBJECT_NOTHING {
            // calculate_object_address: 0 has no address.
            return Err(ZmachineError::ObjectInvalid(object));
        }

        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                // 255 object max
                if object > 255 {
                    self.debug(format!(
                        "calculate_object_address: out of bounds object {}",
                        object
                    ));
                    return Err(ZmachineError::ObjectOutOfBounds(object));
                }

                Ok((self.object_tree_address as usize) + ((object - 1) * OBJECT_ENTRY_SIZE_V3))
            }
        }
    }

    pub fn get_properties_address(&self, object: usize) -> Result<usize, ZmachineError> {
        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                match self.calculate_object_address(object) {
                    Err(msg) => Err(msg),
                    Ok(addr) => match self.get_word(addr + OBJECT_TABLE_PROPERTIES_OFFSET) {
                        Err(msg) => Err(msg),
                        Ok(word) => Ok(word as usize),
                    },
                }
            }
        }
    }

    // Find an object's left sibling
    fn get_left_sibling(&mut self, object: usize) -> Result<u16, ZmachineError> {
        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                // Cleanup old pointer to object, if any
                let mut left_sibling_candidate = self.get_child(self.get_parent(object)?)?;
                if left_sibling_candidate != object {
                    let mut counter = 0;
                    loop {
                        counter += 1; // Catch cycles
                        if counter == OBJECT_TABLE_MAX_CYCLE {
                            return Err(ZmachineError::ObjectCycle(object));
                        }

                        let temp_sib = self.get_sibling(left_sibling_candidate)?;
                        if temp_sib == 0 || temp_sib == object {
                            break;
                        }
                        left_sibling_candidate = temp_sib;
                    }
                }

                Ok(left_sibling_candidate as u16)
            }
        }
    }

    // Insert the object as the first child of the destination. P
    // Previous child, if any, becomes sibling of this object
    // Whatever pointed to this as as sibling (if any) points to previous sibling
    pub fn insert_object(
        &mut self,
        object: usize,
        destination: usize,
    ) -> Result<bool, ZmachineError> {
        // Inserting an object involves
        // If the old parent was nothing, no action needed
        // If this object was the first child of its old parent, old parent's first child should be old sibling
        // If this objcet was not the first child of old parent, it's old left-sibling's sibling should be it's old left sibling
        // Making the object the new child of destination
        // Making the previous child of destination the sibling of this object
        if object == destination {
            // Attempt to add object to itself
            return Err(ZmachineError::ObjectSelfReference(object));
        }

        if object == OBJECT_NOTHING {
            return Ok(true);
        }

        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                let old_parent = self.get_parent(object)?;
                let old_sibling = self.get_sibling(object)?;
                if old_parent != OBJECT_NOTHING {
                    if self.get_child(old_parent)? == object {
                        self.set_byte(
                            self.calculate_object_address(old_parent)? + OBJECT_TABLE_CHILD_OFFSET,
                            old_sibling as u8,
                        )?;
                    } else {
                        let left_sibling = self.get_left_sibling(object)? as u8;
                        if left_sibling == 0 {
                            // Object being inserted is not child of parent, but also has no left siblings
                            return Err(ZmachineError::ObjectInsertError(object));
                        }
                        self.set_byte(
                            self.calculate_object_address(left_sibling as usize)?
                                + OBJECT_TABLE_SIBLING_OFFSET,
                            old_sibling as u8,
                        )?;
                    }
                }

                let object_address = self.calculate_object_address(object)?;
                let old_child = self.get_child(destination)?;
                self.set_byte(
                    object_address + OBJECT_TABLE_SIBLING_OFFSET,
                    old_child as u8,
                )?;
                self.set_byte(
                    object_address + OBJECT_TABLE_PARENT_OFFSET,
                    destination as u8,
                )?;
                self.set_byte(
                    self.calculate_object_address(destination)? + OBJECT_TABLE_CHILD_OFFSET,
                    object as u8,
                )?;
            }
        };

        Ok(true)
    }

    // Remove the object from its current parent. Children stay.
    pub fn remove_object(&mut self, object: usize) -> Result<bool, ZmachineError> {
        // When removing an object:
        // Its new parent is NOTHING
        // Its new sibling is NOTHING
        // If it was the first child, parent's new child is its sibling
        // If it was not the first child of the parent, old left sibling's sibling is its old sibling
        if object == OBJECT_NOTHING {
            return Ok(true);
        }

        let old_parent = self.get_parent(object)?;
        let old_sibling = self.get_sibling(object)?;

        if self.get_child(old_parent)? == object {
            self.set_byte(
                self.calculate_object_address(old_parent)? + OBJECT_TABLE_CHILD_OFFSET,
                old_sibling as u8,
            )?;
        } else if old_parent != OBJECT_NOTHING {
            let left_sibling = self.get_left_sibling(object)? as u8;
            if left_sibling == 0 {
                // Object being removed is not child of parent, but also has no left sibling
                return Err(ZmachineError::ObjectRemoveError(object));
            }
            self.set_byte(
                self.calculate_object_address(left_sibling as usize)? + OBJECT_TABLE_SIBLING_OFFSET,
                old_sibling as u8,
            )?;
        }

        let object_address = self.calculate_object_address(object)?;

        self.set_byte(
            object_address + OBJECT_TABLE_PARENT_OFFSET,
            OBJECT_NOTHING as u8,
        )?;

        self.set_byte(
            object_address + OBJECT_TABLE_SIBLING_OFFSET,
            OBJECT_NOTHING as u8,
        )?;

        Ok(true)
    }

    // Set the property on the given object to the value. If property is length 1, only low byte will be used.
    // If property length > 2, will return 0. otherwise will return the property value
    pub fn set_property(
        &mut self,
        object: usize,
        property: usize,
        val: u16,
    ) -> Result<u16, ZmachineError> {
        let prop_data = self.get_property(object, property)?;
        if prop_data.size == 2 {
            self.set_word(prop_data.start_address, val)?;
            Ok(val)
        } else if prop_data.size == 1 {
            self.set_byte(prop_data.start_address, (val & 0xff) as u8)?;
            Ok(val & 0xff)
        } else {
            Err(ZmachineError::ObjectInvalidPropertySize(prop_data.size))
        }
    }

    // Given an address (assumed to be valid) find the size, property number, property data address
    // and next property address Returns (0,0,0,0) if not found
    fn property_at_address(&self, properties_addr: usize) -> Result<PropertyData, ZmachineError> {
        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                let mut size: usize = 0;
                let mut property_number: usize = 0;
                let mut property_data_address: usize = 0;
                let mut next_property_address: usize = 0;

                let size_byte = self.get_byte(properties_addr)?;
                if size_byte != 0 {
                    size = ((size_byte >> 5) + 1) as usize; // pull upper 3 for size
                    property_number = (size_byte & 0x1f) as usize; // pull lower 5 for property_number
                    property_data_address = properties_addr + 1;
                    next_property_address = properties_addr + (1 + size) as usize;
                    // account for size byte in offset
                }

                Ok(PropertyData {
                    size,
                    property_number,
                    property_data_address,
                    next_property_address,
                })
            }
        }
    }

    // Returns the default value for property # `property`
    pub fn get_default_property(&self, property: usize) -> Result<u16, ZmachineError> {
        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                if property == 0 || property > MAX_PROPERTY_123 {
                    self.debug(format!(
                        "get_default_property: request to read out of bounds default property # {}",
                        property
                    ));
                    return Err(ZmachineError::OutOfBoundsDefaultProperty(property));
                }

                match self
                    .get_word(self.object_table_address as usize + ((property - 1) * WORD_LENGTH))
                {
                    Err(err) => Err(err),
                    Ok(word) => Ok(word),
                }
            }
        }
    }

    // Guess at the last object number based on property list. See notes at bottom of section 12
    pub fn guess_last_object(&self) -> u8 {
        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                let mut object: u8 = 0;
                let mut lowest_property_address: usize = self.get_last_address() as usize;

                loop {
                    if object == 255 {
                        break;
                    }

                    object += 1;

                    match self.calculate_object_address(object as usize) {
                        Err(_) => {
                            break;
                        }
                        Ok(address) => {
                            let prop_addr = self
                                .get_word(address + 7)
                                .expect("Issue fetching property address")
                                as usize;

                            if prop_addr < lowest_property_address {
                                lowest_property_address = prop_addr;
                            }
                            if address + 9 >= lowest_property_address {
                                // First property table is hit, so this was last object
                                break;
                            }
                        }
                    }
                }

                object
            }
        }
    }

    //
    // Text and dictionary
    //

    /// Load the dictionary from the story memory
    /// Will clear any existing dictionary data
    ///
    /// See https://www.inform-fiction.org/zmachine/standards/z1point1/sect13.html
    fn load_dictionary(&mut self) -> Result<bool, ZmachineError> {
        self.dictionary_word_separators.clear();

        // First byte is number of word separators, then each word separator is a byte
        let mut addr = self.dictionary_address as usize;
        for _ in 0..self.get_byte(addr)? {
            addr += BYTE_LENGTH;
            self.dictionary_word_separators.push(self.get_byte(addr)?);
        }

        // Next is the entry length. This has a minimum that varies by version.
        addr += BYTE_LENGTH;
        self.dictionary_entry_length = self.get_byte(addr)? as usize;
        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                if self.dictionary_entry_length < MIN_DICTIONARY_ENTRY_LENGTH_V123 {
                    return Err(ZmachineError::DictionaryLengthOutOfBound(
                        self.dictionary_entry_length,
                    ));
                }
            }
        }

        // Next is the entry count
        addr += BYTE_LENGTH;
        let entry_count = self.get_word(addr)? as usize;
        let mut dictionary_words = Vec::with_capacity(entry_count);
        addr += WORD_LENGTH;

        // Finally the entries. These consist of a word (length varies based on version)
        // and the entry data
        // See 13.3
        for _ in 0..entry_count {
            match self.version {
                ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                    dictionary_words.push(DictionaryWord {
                        address: addr,
                        text: self.text_to_utf(addr, DICTIONARY_WORD_SIZE_V123, false)?,
                    });
                    addr += DICTIONARY_WORD_SIZE_V123
                        + (self.dictionary_entry_length - DICTIONARY_WORD_SIZE_V123);
                }
            }
        }

        self.dictionary_words = dictionary_words;

        Ok(true)
    }

    fn map_zchar_to_shift(&self, idx: usize) -> usize {
        match idx {
            0 => 10,
            1 => 5,
            _ => 0,
        }
    }

    /// Parse input text from the player and place in in the buffer
    ///
    /// Assume text buffer already has text added. Assumes byte 0 of textbuffer has max length of buffer,
    /// so parsing starts at 1
    ///
    /// Returns count of words in buffer
    ///
    /// See end of https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#read
    pub fn parse_input_text(
        &mut self,
        text_addr: u16,
        parse_addr: u16,
    ) -> Result<u8, ZmachineError> {
        // Byte 0 contains max number of words -- stop when this number of words hit
        let max_words = self.get_byte_bounds_check(parse_addr as usize)?;

        // Split input text into words and store indexes. Skip first byte of text buffer, as
        // it will have size
        let mut words = self.split_text(text_addr as usize + BYTE_LENGTH)?;
        if words.len() > max_words as usize {
            words.truncate(max_words as usize);
        }

        // Write number of words to byte 1
        self.set_byte_bounds_check(parse_addr as usize + BYTE_LENGTH, words.len() as u8)?;

        // Loop through each word and write 4 bytes -- word containing address, then byte w/ letter count, then byte with text-buffer index of word
        // "Interpreters are asked to halt with a suitable error message if the text or parse buffers have length of less than 3 or 6 bytes, respectively"
        let mut addr = (parse_addr as usize) + BYTE_LENGTH + BYTE_LENGTH; // First byte is max words, second is number of words found
        for word in words {
            let word_len = word.word.len();
            let dw = self.dictionary_lookup(word.word)?;
            self.set_word(
                addr,
                match dw {
                    Some(dw) => dw.address as u16,
                    None => 0x0000,
                },
            )?;
            addr += WORD_LENGTH;
            self.set_byte_bounds_check(addr, word_len as u8)?;
            addr += BYTE_LENGTH;
            self.set_byte_bounds_check(addr, word.index as u8 + BYTE_LENGTH as u8)?;
            addr += BYTE_LENGTH;
        }

        Ok(max_words)
    }

    /// Find a word in the dictionary. Returns the address of the word if found.
    ///
    /// See end of https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#read
    pub fn dictionary_lookup(
        &self,
        text: Vec<u8>,
    ) -> Result<Option<DictionaryWord>, ZmachineError> {
        let encoded_word = self.dictionary_encode(text);
        for word in self.dictionary_words.iter() {
            let word_size = match self.version {
                ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => DICTIONARY_WORD_SIZE_V123,
            };

            let mut matched = true;

            // This is an inefficient way to do the lookup. The addresses are ordered in
            // ascending address order, so a binary search could be used
            #[allow(clippy::needless_range_loop)]
            for i in 0..word_size {
                if encoded_word[i] != self.get_byte(word.address + i)? {
                    matched = false;
                    break;
                }
            }

            if matched {
                return Ok(Some(word.clone()));
            }
        }

        Ok(Option::None)
    }

    /// Encode a word (as a vector of ZSCII bytes) into an array suitable for comparing
    /// with dictionary. Note the longer dictionary entry size for V4 is used even for V1-3
    ///
    /// See 3.7
    ///
    pub fn dictionary_encode(&self, text: Vec<u8>) -> [u8; DICTIONARY_WORD_SIZE] {
        // Encoded values starts as all 5's per 3.7
        let mut encoded: [u16; DICTIONARY_WORD_SIZE / 2] = [0, 0, 0];

        let mut mapped: u16 = 0;

        let mut shift = 0;
        let mut char_count = 0;

        for i in 0..text.len() {
            let mut found = false;

            // Lowercase
            let c = zscii_lowercase(text[i]);

            for (j, a0c) in A0_CHARS.iter().enumerate() {
                if c == *a0c {
                    shift = 0;
                    found = true;
                    mapped = j as u16;
                    break;
                }
            }

            if !found {
                // No A1 as everything is lowercase
                for (j, a2c) in A2_CHARS.iter().enumerate() {
                    if c == *a2c {
                        shift = match self.version {
                            ZCodeVersion::V1 | ZCodeVersion::V2 => {
                                if shift > 0 {
                                    0 // Don't shift twice for same character
                                } else {
                                    // See 3.7.1, need to look-ahead
                                    if i + 1 < text.len() {
                                        let c2 = zscii_lowercase(text[i + 1]);
                                        if A2_CHARS.contains(&c2) {
                                            SHIFT_LOCK_DOWN
                                        } else {
                                            SHIFT_DOWN
                                        }
                                    } else {
                                        SHIFT_DOWN
                                    }
                                }
                            }
                            ZCodeVersion::V3 => SHIFT_LOCK_DOWN,
                        };
                        found = true;
                        mapped = j as u16;
                        break;
                    }
                }
            }

            if found && mapped != 0 {
                if shift > 0 {
                    encoded[char_count / 3] ^=
                        (shift as u16) << self.map_zchar_to_shift(char_count % 3);
                    char_count += 1;
                }
                let word_index = char_count / 3;
                encoded[word_index] ^= mapped << self.map_zchar_to_shift(char_count % 3);
                char_count += 1;
            }

            match self.version {
                ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                    // 4 bytes = 6 chars. Throw away additional.
                    if char_count > 6 {
                        break;
                    }
                }
            }
        }

        // Pad with 5's
        for i in char_count..9 {
            let word_index = i / 3;
            let shift = self.map_zchar_to_shift(i % 3);
            encoded[word_index] ^= (SHIFT_LOCK_DOWN as u16) << shift;
        }

        // Set high bit of last word to indicate end
        match self.version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                encoded[1] ^= 0x8000;
            }
        };

        [
            ((encoded[0] & 0xff00) >> 8) as u8,
            (encoded[0] & 0x00ff) as u8,
            ((encoded[1] & 0xff00) >> 8) as u8,
            (encoded[1] & 0x00ff) as u8,
            ((encoded[2] & 0xff00) >> 8) as u8,
            (encoded[2] & 0x00ff) as u8,
        ]
    }

    /// Split words (stored in memory) and return as byte vectors
    /// Assumes null-terminated string
    ///
    /// See 13.6.1
    pub fn split_text(&mut self, addr: usize) -> Result<Vec<IndexedWord>, ZmachineError> {
        let mut v = Vec::new();
        let mut index = 0;
        let mut last_char_was_separator = false;

        let mut s = IndexedWord {
            word: Vec::new(),
            index: 0,
        };

        loop {
            let b = self.get_byte(addr + index)?;
            if b == 0 {
                if !s.word.is_empty() {
                    v.push(s);
                }
                break;
            } else if b == ZSCII_SPACE {
                index += 1;
                last_char_was_separator = true;
            } else if self.dictionary_word_separators.contains(&b) {
                // Separators are added as words
                v.push(s);
                s = IndexedWord {
                    word: Vec::new(),
                    index,
                };
                s.word.push(b);
                index += 1;
                last_char_was_separator = true;
            } else {
                if last_char_was_separator {
                    v.push(s);
                    s = IndexedWord {
                        word: Vec::new(),
                        index,
                    };
                    last_char_was_separator = false;
                }
                s.word.push(b);
                index += 1;
            }
        }

        Ok(v)
    }

    /// Handling lexing and looking up text in dictionary
    ///  
    /// See https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#read
    fn handle_input_text(
        &mut self,
        input_text: String,
        text_addr: u16,
        parse_addr: u16,
    ) -> Result<bool, ZmachineError> {
        // Handle the action input text
        // Set the buffers to the text
        let mut addr = text_addr as usize + BYTE_LENGTH;
        for c in input_text.chars() {
            self.set_byte(addr, self.utf_to_input_zscii(c)?)?;
            addr += BYTE_LENGTH;
        }
        self.set_byte(addr, 0)?;

        self.parse_input_text(text_addr, parse_addr)?;

        Ok(true)
    }

    fn handle_abbrev(&mut self, prev_zchar: u8, zchar: u8, result: &mut String) {
        // Abbreviations are stored in a table of words as "word addresses". The index
        // for an given abbreviation is determined by the previous char and this char.
        // The word at this table gives the address, when converted
        let index: usize = (32 * (prev_zchar as usize - 1)) + zchar as usize;
        let address: usize = self.convert_word_address(
            self.get_word(self.abbrev_table_address as usize + index * 2)
                .expect("Out of range"),
        );

        self.text_mapper.preserve_state();
        self.text_mapper.reset();

        match self.text_to_utf(address, 0, true) {
            Err(msg) => {
                self.debug(format!("Error finding abbrevation. Error is {:?}", msg));
                result.push_str("ABBREV ERROR");
            }
            Ok(abbrev) => {
                result.push_str(abbrev.as_str());
            }
        }

        self.text_mapper.restore_state();
    }

    /// Map ZSCII to unicode char (see 3.8), handling errors based on error handling rules
    pub fn zscii_to_output_char(&self, zc: u16) -> Result<char, ZmachineError> {
        if zc == 0 {
            // 3.8.2.1
            return Ok('\0');
        }

        if zc == 10 {
            return Ok('\n');
        }

        if (32..=126).contains(&zc) {
            return Ok(zc as u8 as char);
        }

        if (155..=223).contains(&zc) {
            return Ok(DEFAULT_UNICODE_MAPPING[(zc - 155) as usize]);
        }

        Err(ZmachineError::TextInvalidOutputChar(zc))
    }

    // Map unicode to input chars (see 3.8)
    // This also lowercases the input to work wtih the read opcode
    pub fn utf_to_input_zscii(&self, c: char) -> Result<u8, ZmachineError> {
        if c.is_ascii() {
            let n = c as u8;
            match c as u8 {
                ASCII_BACKSPACE => Ok(ZSCII_DELETE), // 3.8.2.2
                ASCII_NEWLINE => Ok(ZSCII_NEWLINE),  // 3.8.2.5
                ASCII_ESCAPE => Ok(ZSCII_ESCAPE),    // 3.8.2.6,
                32..=64 => Ok(n),
                65..=90 => Ok(n + 32), // Lowercase any uppercase characters
                91..=126 => Ok(n),
                155..=223 => {
                    for uc in DEFAULT_UNICODE_MAPPING.iter() {
                        if *uc == c {
                            return Ok(n);
                        }
                    }

                    Err(ZmachineError::TextInvalidInputChar(c))
                }
                _ => Err(ZmachineError::TextInvalidInputChar(c)),
            }
        } else {
            Err(ZmachineError::TextInvalidInputChar(c))
        }
    }

    pub fn text_to_utf(
        &mut self,
        address: usize,
        length: usize,
        is_abbrev_lookup: bool,
    ) -> Result<String, ZmachineError> {
        match self.text_to_utf_and_addr(address, length, is_abbrev_lookup) {
            Err(msg) => Err(msg),
            Ok(s) => Ok(s.string),
        }
    }

    ///
    /// Extract the ZCode string, as utf, at the given address
    /// and return both it and the address directly after the string
    ///
    fn text_to_utf_and_addr(
        &mut self,
        address: usize,
        length: usize,
        is_abbrev_lookup: bool,
    ) -> Result<StringAndAddress, ZmachineError> {
        // See https://www.inform-fiction.org/zmachine/standards/z1point1/sect03.html
        let mut result = String::new();
        let mut done = false;
        let mut index = 0;
        let mut state = TextParseState::Normal;
        let mut zchars: [u8; 6] = [0, 0, 0, 0, 0, 0];

        if !is_abbrev_lookup {
            self.text_mapper.reset();
        }

        while !done {
            let word = self.get_word(address + (index * 2))?;

            // Bit 7 of first byte will be 1 if last word
            done = word & 0x8000 > 0;

            zchars[3] = ((word & 0x7C00) >> 10) as u8; // First char is hi  6,5,4,3,2
            zchars[4] = ((word & 0x03E0) >> 5) as u8; // Second char is hi 1,0 and lo 7,6,5
            zchars[5] = (word & 0x001F) as u8; // Third char is lo 4,3,2,1,0

            for i in 3..6 {
                let zc = zchars[i];
                match state {
                    TextParseState::Normal => {
                        // In the normal state, print the text, handle any shifts, and switch states
                        // to abbrevations or extended where appropriate
                        let mapped = self.text_mapper.map(zc);
                        match mapped {
                            NOPRINT_CHAR => {
                                // Could include shifts, ignore
                            }
                            ABBREV_1 | ABBREV_2 | ABBREV_3 => {
                                state = TextParseState::Abbrev;
                            }
                            TOGGLE_EXTENDED => {
                                state = TextParseState::ExtendedChar1;
                            }
                            _ => {
                                match self.zscii_to_output_char(mapped as u16) {
                                    Err(_) => {
                                        match self.error_mode {
                                            ErrorMode::Ignore => {
                                                // Log error, add a ? for the text
                                                self.debug(format!(
                                                    "Unable to print invalid ZSCII char {}",
                                                    mapped
                                                ));
                                                result.push('?');
                                            }
                                            ErrorMode::Panic => {
                                                self.debug(format!(
                                                    "Unable to print invalid ZSCII char {}",
                                                    mapped
                                                ));
                                                return Err(ZmachineError::TextInvalidZscii(
                                                    mapped as u16,
                                                ));
                                            }
                                        }
                                    }
                                    Ok(c) => {
                                        result.push(c);
                                    }
                                }
                            }
                        }
                    }
                    TextParseState::Abbrev => {
                        // Abbrevs simply print based of this and previous character, then return to normal
                        self.handle_abbrev(zchars[i - 1], zc, &mut result);
                        state = TextParseState::Normal;
                    }
                    TextParseState::ExtendedChar1 => {
                        // Simply waiting for second char
                        state = TextParseState::ExtendedChar2;
                    }
                    TextParseState::ExtendedChar2 => {
                        // In extended, convert two chars into single char, then map that
                        let mapped = ((zchars[i - 1] << 5) as u16) | (zc as u16);

                        match self.zscii_to_output_char(mapped as u16) {
                            Err(_) => {
                                match self.error_mode {
                                    ErrorMode::Ignore => {
                                        // Log error, add a ? for the text
                                        self.debug(format!(
                                            "Unable to print invalid ZSCII char {}",
                                            mapped
                                        ));
                                    }
                                    ErrorMode::Panic => {
                                        self.debug(format!(
                                            "Unable to print invalid ZSCII char {}",
                                            mapped
                                        ));
                                        return Err(ZmachineError::TextInvalidZscii(mapped));
                                    }
                                }
                            }
                            Ok(c) => {
                                result.push(c);
                            }
                        }
                        state = TextParseState::Normal;
                    }
                }
            }

            // Rotate zchars into history for use with abbrevs/extended
            zchars[0] = zchars[3];
            zchars[1] = zchars[4];
            zchars[2] = zchars[5];

            index += 1;
            if length > 0 && index >= length {
                done = true;
            }
        }

        // Index will be one higher than the index of the final string address
        Ok(StringAndAddress {
            address: address + (index * 2),
            string: result,
        })
    }

    //
    // Memory access
    //

    // Set the word to the value. Return the value set, or error
    pub fn set_word(&mut self, address: usize, value: u16) -> Result<u16, ZmachineError> {
        if address + 1 > self.memory.len() {
            self.debug(format!(
                "set_word(): attempt to set word at {} when length is {}",
                address,
                self.memory.len()
            ));
            return Err(ZmachineError::MemoryOutOfBoundsWrite(address));
        }

        self.memory[address] = (value >> 8) as u8;
        self.memory[address + 1] = value as u8;

        Ok(value)
    }

    /// Set the byte to the value. Return the value set, or error if bounds issue
    pub fn set_byte(&mut self, address: usize, value: u8) -> Result<u8, ZmachineError> {
        if address > self.memory.len() {
            self.debug(format!(
                "set_byte(): attempt to set word at {} when length is {}",
                address,
                self.memory.len()
            ));
            return Err(ZmachineError::MemoryOutOfBoundsWrite(address));
        }

        self.memory[address] = value;

        Ok(value)
    }

    /// Set the byte to the value, first checking that the interpreter can write to this location
    pub fn set_byte_bounds_check(
        &mut self,
        address: usize,
        value: u8,
    ) -> Result<u8, ZmachineError> {
        if !self.is_writeable(address) {
            Err(ZmachineError::MemoryOutOfBoundsWrite(address))
        } else {
            self.set_byte(address, value)
        }
    }

    /// Set the bytes starting at the address.
    pub fn set_bytes(&mut self, address: usize, bytes: Vec<u8>) -> Result<(), ZmachineError> {
        for (pos, b) in bytes.iter().enumerate() {
            self.set_byte(address + pos, *b)?;
        }

        Ok(())
    }

    /// Generate a checksum for the entrity of the stack
    pub fn calculate_stack_checksum(&self) -> u16 {
        let mut checksum: usize = 0;

        for local in self.stack.iter() {
            checksum += (*local) as usize;
        }
        (checksum % u16::max_value() as usize) as u16
    }

    /// Generate a checksum for the entirity of memory. Useful for debugging
    pub fn calculate_memory_checksum(&self) -> u16 {
        let mut checksum: u16 = 0;

        for b in self.memory.iter() {
            let b16 = *b as u16;
            let s = checksum as usize + b16 as usize;
            if s > u16::max_value() as usize {
                checksum = (s - (u16::max_value() as usize)) as u16;
            } else {
                checksum += b16;
            }
        }

        checksum
    }

    // Set the variable to the value. Returns the value set, or error if any issues {
    pub fn set_variable(&mut self, variable_number: u8, value: u16) -> Result<u16, ZmachineError> {
        if variable_number == STACK_VARIABLE {
            // Stack
            match self.routine_stack.last_mut() {
                None => {
                    return Err(ZmachineError::MemoryStackOverflowRoutine());
                }
                Some(_routine) => {
                    self.stack.push(value);
                }
            }
        } else if variable_number <= MAX_LOCAL_VAR {
            match self.routine_stack.last_mut() {
                None => {
                    return Err(ZmachineError::MemoryStackOverflowRoutine());
                }
                Some(routine) => {
                    if (variable_number - 1) as usize >= routine.local_variables.len() {
                        println!(
                            "Request to set variable {} to {} when local vars length is {}",
                            variable_number,
                            value,
                            routine.local_variables.len()
                        );
                        return Err(ZmachineError::RoutineLocalVariableOutOfBounds(
                            variable_number as usize,
                        ));
                    }
                    routine.local_variables[(variable_number - 1) as usize] = value;
                }
            }
        } else {
            let offset: usize =
                (variable_number as usize - MAX_LOCAL_VAR as usize - 1) * WORD_LENGTH;
            self.set_word(self.global_variable_address as usize + offset, value)?;
        }

        Ok(value)
    }

    // Set/clear the specified bit at the address. Bit 0 is the rightmost (least significant)
    pub fn set_bit(&mut self, address: usize, bit: u8, value: bool) -> Result<bool, ZmachineError> {
        if address > self.memory.len() {
            self.debug(format!(
                "set_bit(): attempt to write bit at {} when length is {}",
                address,
                self.memory.len()
            ));
            return Err(ZmachineError::MemoryOutOfBoundsWrite(address));
        }

        if bit > 7 {
            self.debug(format!(
                "set_bit(): attempt to write invalid bit {} at address {}",
                bit, address
            ));
            return Err(ZmachineError::MemoryInvalidBit(address, bit));
        }

        if value {
            self.memory[address] |= 0x01 << bit;
        } else {
            self.memory[address] &= (0x01 << bit) ^ 0xff;
        }

        Ok(value)
    }

    //
    // Accessors
    //

    /// Set the internal transcript bit on/off. If toggling transcript
    /// from terp, need to use this to keep vm in sync
    pub fn set_transcript_bit(&mut self, b: bool) {
        if self.set_bit(HEADER_FLAGS_2, 0, b).is_err() {
            println!("VM ERROR: Unable to toggle transcript bit to {}", b);
        }
    }

    // Return the largest address in the memory
    pub fn get_last_address(&self) -> usize {
        self.memory.len()
    }

    pub fn get_version(&self) -> ZCodeVersion {
        self.version
    }

    pub fn get_status_mode(&self) -> StatusMode {
        self.status_mode
    }

    pub fn get_file_length(&self) -> usize {
        self.file_length
    }

    pub fn get_checksum(&self) -> u16 {
        self.checksum
    }

    pub fn get_release_number(&self) -> u16 {
        self.release_number
    }

    pub fn get_inform_version(&self) -> &str {
        self.inform_version.as_str()
    }

    pub fn get_serial(&self) -> &str {
        self.serial.as_str()
    }

    //
    // Debugging
    //

    /// Set a the local variable in question even if the current routine
    /// does not have that local. Will create any locals inbetween.
    pub fn force_set_local(&mut self, var: usize, val: u16) {
        // Var is between 1 and 15
        let converted_var = var - 1;
        if converted_var < 15 {
            let top_routine = self.routine_stack.last_mut().unwrap();
            for _i in top_routine.local_variables.len()..=converted_var {
                top_routine.local_variables.push(0);
            }
            top_routine.local_variables[converted_var] = val;
        }
    }

    /// Generates a string representing the current state of the VM
    /// Useful for debugging
    pub fn get_state_string(&self) -> String {
        let mut rs = String::new();
        for routine in self.routine_stack.iter() {
            rs.push(' ');
            rs.push('[');
            rs.push_str(&routine.get_state_string());
            rs.push(']');
        }

        format!(
            "S ({:?}) M ({:04X}) PC ({:06X}) ST ({:04X}){}",
            self.state,
            self.calculate_memory_checksum(),
            self.pc,
            self.calculate_stack_checksum(),
            rs
        )
    }

    pub fn dump_dictionary(&self) {
        print!("Word separators: ");
        for c in self.dictionary_word_separators.iter() {
            print!(
                "{}",
                self.zscii_to_output_char((*c) as u16)
                    .expect("Error converting zscii in word separator")
            );
        }
        println!();
        println!("Word size:       {}", self.dictionary_entry_length);
        println!("Word count:      {}", self.dictionary_words.len());
        for i in 0..self.dictionary_words.len() {
            println!(
                "[{}] {} (0x{:4X}{:4X})",
                i,
                self.dictionary_words[i].text,
                self.get_word(self.dictionary_words[i].address).expect("OK"),
                self.get_word(self.dictionary_words[i].address + WORD_LENGTH)
                    .expect("OK"),
            );
        }
    }

    pub fn dump_header(&self, infodump: bool) {
        if infodump {
            println!("    **** Story file header ****");
            println!();
            match self.get_version() {
                ZCodeVersion::V1 => {
                    println!("Z-code version:           1");
                }
                ZCodeVersion::V2 => {
                    println!("Z-code version:           2");
                }
                ZCodeVersion::V3 => {
                    println!("Z-code version:           3");
                }
            };
            match self.get_status_mode() {
                StatusMode::Score => {
                    println!("Interpreter flags:        Display score/moves");
                }
                StatusMode::Time => {
                    println!("Interpreter flags:        Display time");
                }
            };
            println!("Release number:           {}", self.get_release_number());
            println!("Size of resident memory:  {:04x}", self.high_memory_address);
            println!("Start PC:                 {:04x}", self.initial_pc_address);
            println!("Dictionary address:       {:04x}", self.dictionary_address);
            println!(
                "Object table address:     {:04x}",
                self.object_table_address
            );
            println!(
                "Global variables address: {:04x}",
                self.global_variable_address
            );
            println!(
                "Size of dynamic memory:   {:04x}",
                self.static_memory_address
            );
            println!("Game flags:               None");
            println!("Serial number:            {}", self.get_serial());
            println!(
                "Abbreviations address:    {:04x}",
                self.abbrev_table_address
            );
            if self.file_length > 0 {
                println!("File size:                {:05x}", self.file_length);
                println!("Checksum:                 {:04x}", self.checksum);
            }

            if self.inform_version != "\0\0\0\0" {
                // Currently just hardcoded to match tests since not supported yet
                println!("Header extension address: 0102");
                println!("Inform Version:           {}", self.inform_version);
                println!("Header extension length:  0003");
                println!("Unicode table address:    0000");
            }
        } else {
            println!("Version:        {:?}", self.get_version());
            println!("Release Number: {}", self.get_release_number());
            println!("Serial:         {}", self.get_serial());
            println!("Inform Version: {}", self.get_inform_version());
            println!();
            println!("Static memory:  {:#06X}", self.static_memory_address);
            println!("High memory:    {:#06X}", self.high_memory_address);
            println!("Initial PC:     {:#06X}", self.initial_pc_address);
            println!("Dictionary:     {:#06X}", self.dictionary_address);
            println!("Object Table:   {:#06X}", self.object_table_address);
            println!("Globals:        {:#06X}", self.global_variable_address);
            println!("Static memory:  {:#06X}", self.static_memory_address);
            println!("Abbreviations:  {:#06X}", self.abbrev_table_address);
            println!();
            println!("Status mode:    {:?}", self.get_status_mode());
            println!("File length:    {:}", self.get_file_length());
            println!("Checksum:       {:#04X}", self.get_checksum());
            println!("Story len:      {}", self.story.len()); // This is here to skip the dead code warning
            println!();
            // Note these are set by the interpreter itself, here for testing
            println!(
                "Spec Revision:  {:#06X}",
                self.get_word(HEADER_REVISION_NUMBER).expect("Whoops!")
            );
            println!(
                "Story split?    {}",
                self.get_bit(HEADER_FLAGS_1, 2).expect("Whoops!")
            );
            println!(
                "Tandy?          {}",
                self.get_bit(HEADER_FLAGS_1, 3).expect("Whoops!")
            );
            println!(
                "Status unavail? {}",
                self.get_bit(HEADER_FLAGS_1, 4).expect("Whoops!")
            );
            println!(
                "Split avail?    {}",
                self.get_bit(HEADER_FLAGS_1, 5).expect("Whoops!")
            );
            println!(
                "Variable pitch? {}",
                self.get_bit(HEADER_FLAGS_1, 6).expect("Whoops!")
            );
            println!(
                "Transcript?     {}",
                self.get_bit(HEADER_FLAGS_2, 0).expect("Whoops!")
            );
        }
    }

    pub fn dump_objects(&self, max_object: usize) -> String {
        let mut s = String::new();

        for i in 1..=max_object {
            let parent = self.get_parent(i).expect("Get parent failed");
            let child = self.get_child(i).expect("Get child failed");
            let sibling = self.get_sibling(i).expect("Get sibling failed");
            s.push_str(format!("[{}: P{} C{} S{}]", i, parent, child, sibling).as_str());
        }

        s
    }

    pub fn dump_state(&self) -> String {
        let mut s = String::new();

        s.push_str("Default Properties:\n");
        for i in 1..32 {
            s.push_str(format!("{}) {}\n", i, self.get_default_property(i).expect("ok")).as_str());
        }

        s.push_str("Variables\n");

        for variable_number in 0..255 {
            if variable_number == 0 {
                s.push_str("(SP)");
            } else if variable_number < 16 {
                s.push_str(format!("L{:02x}", variable_number - 1).as_str());
            } else {
                s.push_str(format!("G{:02x}", variable_number - 16).as_str());
            }

            let v = match self.peek_variable(variable_number, false) {
                Ok(n) => n,
                Err(_msg) => 0,
            };

            s.push_str(format!(": 0x{:04X} ({})\n", v, v).as_str());
        }

        s
    }

    pub fn dump_memory(&self, start_address: usize, end_address: usize, width: usize) {
        let mut i = start_address;
        while i < end_address {
            print!("{:#08X}", i);

            for _ in 0..width {
                if i < self.memory.len() {
                    print!(" {:02X}", self.memory[i]);
                } else {
                    print!("   ");
                }
                i += 1;
            }

            println!();
        }
    }

    pub fn set_debug_verbosity(&mut self, v: DebugVerbosity) {
        self.debug_verbosity = v;
    }
}

/// Convert a ZSCII char to lowercase
fn zscii_lowercase(c: u8) -> u8 {
    match c {
        0x41..=0x5A => c + 32,
        _ => c,
    }
}

pub fn load_compressed_save_data(
    compressed_data: &[u8],
    static_memory_address: u16,
    story: &[u8],
    memory: &mut [u8],
) -> Result<(), ZmachineError> {
    // See quetzal spec 3.2 for compression scheme. Note this function will mutate
    // the game memory directly
    let mut idx: usize = 0;
    let mut last_byte_zero = false;

    for byte in compressed_data.iter() {
        if idx > static_memory_address as usize {
            return Err(ZmachineError::SaveDataOverflowError());
        }

        if idx > story.len() {
            return Err(ZmachineError::SaveDataOverflowError());
        }

        // All values are xored with existing data
        if last_byte_zero {
            // Follow with *byte bytes of zeros
            // Note it is legal to have two 0 bytes in a row. This represents a
            // single 0
            for _i in 0..*byte {
                memory[idx] = story[idx];
                idx += 1;
            }
            last_byte_zero = false;
        } else if *byte == 0 {
            // Zero bytes are stored as a run
            last_byte_zero = true;
            memory[idx] = story[idx];
            idx += 1;
        } else {
            // Non-zero bytes stored as byte value
            memory[idx] = *byte ^ story[idx];
            idx += 1;
        }
    }

    // Queztal 3.4 -- any additional data is zeros
    while idx < static_memory_address as usize {
        memory[idx] = story[idx];
        idx += 1;
    }

    Ok(())
}

pub fn compress_story_data(dynamic_memory_end: usize, story: &[u8], memory: &[u8]) -> Vec<u8> {
    // See quetzal spec 3.2 for compression scheme.
    let mut data = vec![];
    let mut idx: usize = 0;

    while idx < dynamic_memory_end as usize {
        let byte: u8 = memory[idx] ^ story[idx];
        if byte != 0 {
            // Non zero bytes stored as xor with original story data
            data.push(byte);
            idx += 1;
        } else {
            // Zero bytes stored as 0 followed by length byte
            let mut run_length = 0;
            idx += 1;
            data.push(0);
            // // Keep going until non-zero, hit memory top, or hit max byte size
            while memory[idx] ^ story[idx] == 0 && idx < dynamic_memory_end && run_length < 255 {
                idx += 1;
                run_length += 1;
            }
            data.push(run_length);
        }
    }

    data
}
