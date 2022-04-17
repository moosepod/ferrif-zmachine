pub const ZMACHINE_TRUE: u16 = 1;
pub const ZMACHINE_FALSE: u16 = 0;

// These are included for readability, not because they might change in future implementations
pub const WORD_LENGTH: usize = 2;
pub const BYTE_LENGTH: usize = 1;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ZCodeVersion {
    V1,
    V2,
    V3,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum DebugVerbosity {
    None,
    All,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum WindowLayout {
    Lower,
    Upper,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum InputStreamEnum {
    Keyboard,
    File,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OutputStreamEnum {
    Screen,
    Transcript,
    Memory,
    Commands,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ZmachineError {
    // Memory
    MemoryOutOfBoundsRead(usize),
    MemoryOutOfBoundsWrite(usize),
    MemoryInvalidBit(usize, u8),
    MemoryStackOverflowGame(),
    MemoryStackOverflowRoutine(),
    MemoryInvalidLocalVariable(u8),
    // Text
    TextInvalidZscii(u16),
    TextInvalidInputChar(char),
    TextInvalidOutputChar(u16),
    // Objects
    OutOfBoundsDefaultProperty(usize),
    OutOfBoundsAttribute(u8),
    ObjectInvalidPropertySize(usize),
    ObjectInvalidProperty(usize),
    ObjectRemoveError(usize),
    ObjectInsertError(usize),
    ObjectSelfReference(usize),
    ObjectCycle(usize),
    ObjectOutOfBounds(usize),
    ObjectInvalid(usize),
    // Routines
    RoutineLocalVariableOutOfBounds(usize),
    // Dictionary
    DictionaryLengthOutOfBound(usize),
    // Save/Restore
    SaveReleaseNumberMismatch(u16, u16),
    SaveChecksumMismatch(u16, u16),
    SaveSerialNumberMismatch([u8; 6]),
    SaveDataOverflowError(),
    SaveDataMemoryMismatch(),
    // Instructions
    InstructionsExpected1Operand(),
    InstructionsExpected2Operands(),
    InstructionsExpected3Operands(),
    InstructionsOperandVariableOutOfBounds(u16),
    InstructionsUnsupportedOperandType(),
    InstructionsUnreachable(),
    InstructionsShortForm2OP(),
    InstructionsInvalid2OP(),
    InstructionsUnhandledInstruction(u8),
    InstructionVersionMismatch(),
    InstructionPrintCharOutOfRange(u16),
    InstructionMissingAddress(),
    InstructionsDivideByZero(),
    InstructionsInvalidSetWindowValue(),
    InstructionsUnsupportedInputStream(),
    InstructionsUnsupportedOutputStream(),
    // Misc
    TableWriteOverflow(),
    MemoryStreamOverflow(),
}

///
/// Rather than mutate the vm/screen state directly, instructions return Actions.
/// This makes it easy to create an undo/redo system
/// One goal was to keep memory allocation to a minimum, which result in several
/// "compound" actions, even though smaller actions returned in a vector would be cleaner
/// I am not sure if this was a good decision or not.
///
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Jump(usize),                                                 // Jump to an address
    Return(u16), // Return from the current routine with the given value
    Quit(),      // Halt execution of the interpreter
    Call(usize, u8, u16, u16, u16, u8, usize), // Call a routine with the given address, argument count, argument values (0 if not specified), store variable and return address
    PrintAddress(usize, usize, bool, bool), // Print a ZChar string starting at the provided address to the current output stream. Second param is pc address (if 0, use end of string).  if bool is true, also perform a return true after print. if second bool is true, prints a newline after other text.
    PrintString(String, usize), // Print a unicode string. First param is string to print, second next addess for pc.
    PrintChar(u16, usize),      // Print the ZSCII char. Second param is next address for pc.
    StoreVariable(u8, u16, usize, bool), // Store into a variable. First param is variable number, second is value to store, third is next address for pc. Last flag is true if this is "in place", meaning if variable is stack, it should be popped first.
    StoreVariableAndReturn(u8, u16, u16), // Store into a variable. First param is variable number, second is value to store, third is return value.
    StoreByte(usize, u8, usize), // Store a byte into memory. Firat param is address, second is byte to store, third is next address for pc
    StoreBytes(usize, Vec<u8>, usize), // Store an array of bytes starting at the address, jumping to address after
    StoreWord(usize, u16, usize), // Store a byte into memory. Firat param is address, second is word to store, third is next address for pc
    ReadLine(u8, u16, u16, usize), // Read a line of text. First param is number of characters, second is address of array to store results, third is address of array for parsed results, last is next adddress for pc
    PopAndStore(u8, usize), // Pop the stack and store it in the provided variable. Then move to next address.
    Pop(usize),             // Pop the stack and toss the value. Then move to next address.
    SetAttr(u16, u8, bool, usize), // Set/clear an objects attribute. First is object number, second is attribute number, third is value, fourth is pc value
    SetProperty(u16, u16, u16, usize), // Set a property. First is object number, second is property number, third is value, last is address. Will fail if property size >  2
    InsertObject(u16, u16, usize), // Insert object under another. First is object, second is new parent, last is address
    RemoveObject(u16, usize), // Remove an object from its parent. First is object,  last is address
    RandomAndStore(u16, u8, usize), // Generate a random integer. First value is max value, second is store variable, third is PC
    ReseedRNGAndStore(u16, u8, usize), // Reseed the RNG and store 0. First value is reseed value (0 0s random), second is store variable, third is PC
    Save(usize, bool, usize), // Attempt to save game. First Var is branch on success, second is invert (ie if false branch on failed), third is is PC (failure)
    Restore(usize, bool, usize), // Attempt to restore game. First Var is branch on success, second is invert (ie if false branch on failed), third is is PC (failure)
    Restart(),                   // Restart game
    SwitchInputStream(InputStreamEnum, usize), // Switch to the given input stream. First Var is stream, second is pc,
    SetOutputStream(OutputStreamEnum, Option<u16>, bool, usize), // Toggle the given output stream on/off. Contains an optional address for memory streams
    SoundEffect(u16, u16, u16, usize), // Play a sound effect. First is number of effect, second is effect, third volume,
    SplitWindow(u16, usize),           // Split the window. First is number of lines, second is PC
    SetWindow(WindowLayout, usize),    // Set the window. First is number to set, second is PC
    ShowStatus(usize),                 // Show the status immediately. First is PC

    Nop(usize), // Do nothing
}

///
/// Methods for reading memory. Any writing is done via actions.
///  
pub trait MemoryReader {
    fn get_byte(&self, address: usize) -> Result<u8, ZmachineError>;
    fn get_byte_bounds_check(&self, address: usize) -> Result<u8, ZmachineError>;
    fn get_bytes(&self, address: usize, length: usize) -> Result<Vec<u8>, ZmachineError>;
    fn get_bit(&self, address: usize, bit: u8) -> Result<bool, ZmachineError>;
    fn get_word(&self, address: usize) -> Result<u16, ZmachineError>;
    fn get_word_bounds_check(&self, address: usize) -> Result<u16, ZmachineError>;
    fn convert_packed_address(&self, address: u16) -> usize;
    fn get_variable(&mut self, variable: u8) -> Result<u16, ZmachineError>;
    fn peek_variable(&self, variable: u8, globals_only: bool) -> Result<u16, ZmachineError>;
    fn get_stack_pointer(&self) -> usize;
    fn verify_checksum(&self, checksum: u16) -> Result<bool, ZmachineError>;
}

// Wraps the info needed for a property's data, which can be variable length
#[derive(Copy, Clone)]
pub struct Property {
    pub object: usize,
    pub property: usize,
    pub size: usize,
    pub start_address: usize,
    pub value: usize,
}

///
/// Methods for reading the object tree. Any changes are done via actions
///
pub trait ObjectTreeReader {
    fn get_attribute(&self, object: usize, attribute: u8) -> Result<bool, ZmachineError>;
    fn get_sibling(&self, object: usize) -> Result<usize, ZmachineError>;
    fn get_child(&self, object: usize) -> Result<usize, ZmachineError>;
    fn get_parent(&self, object: usize) -> Result<usize, ZmachineError>;
    fn get_property_address(&self, object: usize, property: usize) -> Result<usize, ZmachineError>;
    fn get_property_length(&self, property_address: usize) -> Result<usize, ZmachineError>;
    fn get_short_name(&mut self, object: usize) -> Result<String, ZmachineError>;
    fn get_next_property(&self, object: usize, property: usize) -> Result<usize, ZmachineError>;
    fn get_property(&self, object: usize, property: usize) -> Result<Property, ZmachineError>;
}

#[derive(Debug)]
enum InstructionForm {
    Long,
    Short,
    Variable,
}

#[derive(Debug)]
enum OperandCount {
    OP0,
    OP1,
    OP2,
    Var,
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum OperandType {
    Large,
    Small,
    Variable,
    Omitted,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Operand {
    operand_value: u16,
    operand_type: OperandType,
    variable_number: u8, // Will be 0 for non-variable type
}

fn format_return_var(variable_number: u8) -> String {
    let mut s = String::from(" -> ");
    if variable_number == 0 {
        s.push_str("-(SP)");
    } else if variable_number < 16 {
        s.push_str(format!("L{:02x}", variable_number - 1).as_str());
    } else {
        s.push_str(format!("G{:02x}", variable_number - 16).as_str());
    }

    s
}

fn format_variable(variable_number: u8) -> String {
    let mut s = String::new();
    if variable_number == 0 {
        s.push_str("(SP)");
    } else if variable_number < 0x10 {
        s.push_str(format!("L{:02x}", variable_number - 1).as_str());
    } else {
        s.push_str(format!("G{:02x}", variable_number - 0x10).as_str());
    }

    s
}

fn format_operand(operand: Operand) -> String {
    match operand.operand_type {
        OperandType::Small => format!("0x{:02X}", operand.operand_value),
        OperandType::Large => format!("0x{:04X}", operand.operand_value),
        OperandType::Variable => format_variable(operand.variable_number),
        OperandType::Omitted => String::new(),
    }
}

fn make_instruction_text(instruction: &str, operands: &[Operand]) -> String {
    let mut s = String::from(instruction);
    for operand in (*operands).iter() {
        s.push(' ');
        s.push_str(format_operand(*operand).as_str());
    }

    s
}

fn make_instruction_text_jump(instruction: &str, target_address: usize) -> String {
    let mut s = String::from(instruction);
    s.push_str(format!(" 0x{:06X}", target_address).as_str());

    s
}

fn make_instruction_text_store(instruction: &str, operands: &[Operand], store_var: u8) -> String {
    let mut s = String::from(instruction);
    for operand in (*operands).iter() {
        s.push(' ');
        s.push_str(format_operand(*operand).as_str());
    }

    s.push_str(" -> ");
    s.push_str(format_variable(store_var).as_str());

    s
}

fn make_instruction_text_branch(
    instruction: &str,
    operands: &[Operand],
    branch_addr: usize,
    branch_on_true: bool,
) -> String {
    let mut s = String::from(instruction);
    for operand in (*operands).iter() {
        s.push(' ');
        s.push_str(format_operand(*operand).as_str());
    }

    if branch_on_true {
        s.push_str(" [TRUE]");
    } else {
        s.push_str(" [FALSE]");
    }

    if branch_addr == 0 {
        s.push_str(" R0");
    } else if branch_addr == 1 {
        s.push_str(" R1");
    } else {
        s.push_str(format!(" 0x{:06X}", branch_addr).as_str());
    }

    s
}

fn make_instruction_text_branch_and_store(
    instruction: &str,
    operands: &[Operand],
    branch_addr: usize,
    branch_on_true: bool,
    store_var: u8,
) -> String {
    let mut s = make_instruction_text_branch(instruction, operands, branch_addr, branch_on_true);
    s.push_str(" -> ");
    s.push_str(format_variable(store_var).as_str());

    s
}

pub const MAX_UNSIGNED: i32 = 65536;
pub const MAX_SIGNED: u16 = 32767;
///
/// Take a word and convert it to a signed int
/// See https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
///
pub fn word_to_signed(n: u16) -> i16 {
    if n > MAX_SIGNED {
        -(MAX_UNSIGNED - n as i32) as i16
    } else {
        n as i16
    }
}

///
/// Take a signed int and convert it to an unsigned word
/// See https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
///
fn signed_to_word(n: i16) -> u16 {
    if n >= 0 {
        n as u16
    } else {
        (MAX_UNSIGNED as i16 + n) as u16
    }
}

///
/// Take a 14 bit word and convert it to a signed int
/// This is used for branches -- not sure where it is documented?
/// I grabbed it from my python terp
/// See https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
///
fn word_to_signed_14bit(n: u16) -> i16 {
    if n > 0x1fff {
        -(((n as i16) ^ 0x3fff) + 1)
    } else {
        n as i16
    }
}

// Used only in tests right now. Keeping since it's useful to be able
// to reverse word_to_signed_14bit
#[allow(dead_code)]
fn signed_14bit_to_word(n: i16) -> u16 {
    if n >= 0 {
        n as u16
    } else {
        -((n ^ 0x3fff) + 1) as u16
    }
}

#[test]
fn test_word_to_signed() {
    assert_eq!(0, word_to_signed(0));
    assert_eq!(0, signed_to_word(0));

    assert_eq!(1, word_to_signed(1));
    assert_eq!(1, signed_to_word(1));

    assert_eq!(32767, word_to_signed(32767));
    assert_eq!(32767, signed_to_word(32767));

    assert_eq!(65535, signed_to_word(-1));
    assert_eq!(-1, word_to_signed(65535));

    assert_eq!(-2, word_to_signed(65534));
    assert_eq!(65534, signed_to_word(-2));

    assert_eq!(-32768, word_to_signed(32768));

    assert_eq!(0, word_to_signed_14bit(0));
    assert_eq!(0, signed_14bit_to_word(0));

    assert_eq!(1, word_to_signed_14bit(1));
    assert_eq!(1, signed_14bit_to_word(1));

    assert_eq!(-1, word_to_signed_14bit(16383));
    assert_eq!(16383, signed_14bit_to_word(-1));
    assert_eq!(-2, word_to_signed_14bit(16382));
    assert_eq!(16382, signed_14bit_to_word(-2));

    assert_eq!(-0x49, word_to_signed_14bit(0x3fb7));
    assert_eq!(0x3fb7, signed_14bit_to_word(-0x49));
}

///
/// The instruction handler:
/// - looks at the byte pointed to by the pc
/// - identifies the instruction form, operand count, and opcode
/// - dispatches to the appropriate function for the operand count
///
/// It returns an Action indicating the steps to take (or an error if something went wrong),
/// along with an optional textual representation of the instructino
///
/// See https://www.inform-fiction.org/zmachine/standards/z1point1/sect04.html for more details
///
pub fn handle_instruction<T: MemoryReader + ObjectTreeReader>(
    pc: usize,
    reader: &mut T,
    version: ZCodeVersion,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let opcode_byte = reader.get_byte(pc).expect("opcode");
    //print!("0x{:06X}: 0x{:04X} ", pc, opcode_byte);
    // See 4.3
    let form = match (opcode_byte & 0xC0) >> 6 {
        3 => InstructionForm::Variable,
        2 => InstructionForm::Short,
        _ => InstructionForm::Long,
    };

    let opcode = match form {
        // 4.3.1
        InstructionForm::Short => opcode_byte & 0x0F,
        // 4.3.2
        InstructionForm::Long => opcode_byte & 0x1F,
        // 4.3.3
        InstructionForm::Variable => opcode_byte & 0x1F,
    };

    let operand_count = match form {
        // 4.3.1
        InstructionForm::Short => {
            if (opcode_byte & 0x30) >> 4 == 3 {
                OperandCount::OP0
            } else {
                OperandCount::OP1
            }
        }
        // 4.3.2
        InstructionForm::Long => OperandCount::OP2,
        // 4.3.3
        InstructionForm::Variable => {
            if opcode_byte & 0x20 > 0 {
                OperandCount::Var
            } else {
                OperandCount::OP2
            }
        }
    };

    match operand_count {
        OperandCount::OP0 => handle_0op(pc + BYTE_LENGTH, opcode, reader, version, verbosity),
        OperandCount::OP1 => {
            // 4.3.1
            let operand_types = match (opcode_byte & 0x30) >> 4 {
                0x00 => vec![OperandType::Large],
                0x01 => vec![OperandType::Small],
                0x02 => vec![OperandType::Variable],
                _ => return Err(ZmachineError::InstructionsUnsupportedOperandType()),
            };

            let (new_pc, operands) =
                extract_operands(pc + BYTE_LENGTH, reader, operand_types).expect("refactor");

            handle_1op(new_pc, opcode, operands[0], reader, version, verbosity)
        }
        OperandCount::OP2 => {
            // A 2OP-type instruction can receive operands from either a long-form instruction
            // or a Var-form instruction. Handle both
            match form {
                InstructionForm::Variable => {
                    let (pc, operands) =
                        extract_operands_var(pc + BYTE_LENGTH, reader).expect("refactor");

                    handle_2op(pc, opcode, operands, reader, version, verbosity)
                }
                InstructionForm::Long => {
                    // 4.4.2
                    let operand_types = match (opcode_byte & 0x60) >> 5 {
                        0x00 => vec![OperandType::Small, OperandType::Small],
                        0x01 => vec![OperandType::Small, OperandType::Variable],
                        0x02 => vec![OperandType::Variable, OperandType::Small],
                        0x03 => vec![OperandType::Variable, OperandType::Variable],
                        _ => return Err(ZmachineError::InstructionsUnreachable()),
                    };

                    let (new_pc, operands) =
                        extract_operands(pc + BYTE_LENGTH, reader, operand_types)
                            .expect("refactor");
                    handle_2op(
                        new_pc, // Skip opcode byte
                        opcode, operands, reader, version, verbosity,
                    )
                }
                InstructionForm::Short => Err(ZmachineError::InstructionsShortForm2OP()),
            }
        }
        OperandCount::Var => handle_var(pc + BYTE_LENGTH, opcode, reader, version, verbosity),
    }
}

const RESTORE_PLACEHOLDER_OPCODE: u8 = 0xef;
const SAVE_PLACEHOLDER_OPCODE: u8 = 0xff;

pub fn handle_0op<T: MemoryReader + ObjectTreeReader>(
    pc: usize,
    opcode: u8,
    reader: &mut T,
    version: ZCodeVersion,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    match opcode {
        0x00 => rtrue(verbosity),
        0x01 => rfalse(verbosity),
        0x02 => zprint(pc, verbosity),
        0x03 => zprint_ret(pc, verbosity),
        0x05 => handle_branch_instruction(
            pc,
            SAVE_PLACEHOLDER_OPCODE,
            vec![],
            reader,
            version,
            verbosity,
        ),
        0x06 => handle_branch_instruction(
            pc,
            RESTORE_PLACEHOLDER_OPCODE,
            vec![],
            reader,
            version,
            verbosity,
        ),
        0x07 => restart(verbosity, version),
        0x08 => ret_popped(reader, verbosity),
        0x09 => pop(pc, verbosity),
        0x0A => zquit(verbosity),
        0x0B => new_line(pc, verbosity),
        0x0C => show_status(pc, verbosity, version),
        0x0D => handle_branch_instruction(pc, opcode, vec![], reader, version, verbosity),
        _ => {
            println!("Unhandled 0OP instruction with opcode 0x{:02X}", opcode);
            Err(ZmachineError::InstructionsUnhandledInstruction(opcode))
        }
    }
}

pub fn handle_1op<T: MemoryReader + ObjectTreeReader>(
    pc: usize,
    opcode: u8,
    op1: Operand,
    reader: &mut T,
    version: ZCodeVersion,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let store_pc = pc + BYTE_LENGTH;
    let store_val = reader.get_byte(pc)?;

    match opcode {
        0x00 => handle_branch_instruction(pc, 0x00, vec![op1], reader, version, verbosity),
        0x01 => handle_branch_and_store_instruction(
            store_pc, 0x01, op1, store_val, reader, version, verbosity,
        ),
        0x02 => handle_branch_and_store_instruction(
            store_pc, 0x02, op1, store_val, reader, version, verbosity,
        ),
        0x03 => get_parent(store_pc, op1, store_val, reader, verbosity),
        0x04 => get_prop_len(store_pc, op1, store_val, reader, verbosity),
        0x05 => inc(pc, op1, reader, verbosity),
        0x06 => dec(pc, op1, reader, verbosity),
        0x07 => print_addr(pc, op1, verbosity),
        0x0B => ret(op1, verbosity),
        0x09 => remove_obj(pc, op1, verbosity),
        0x0A => print_obj(pc, op1, reader, verbosity),
        0x0C => jump(pc, op1, verbosity),
        0x0D => print_paddr(pc, op1, reader, verbosity),
        0x0e => load(store_pc, reader, op1, store_val, verbosity),
        0x0f => znot(store_pc, op1, store_val, verbosity),
        _ => {
            println!("Unhandled 1OP instruction with opcode 0x{:02X}", opcode);
            Err(ZmachineError::InstructionsUnhandledInstruction(opcode))
        }
    }
}

// If a 2OP is called in Var form it can have more than 2 operand, confusingly enough
pub fn handle_2op<T: MemoryReader + ObjectTreeReader>(
    pc: usize,
    opcode: u8,
    operands: Vec<Operand>,
    reader: &mut T,
    version: ZCodeVersion,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let store_pc = pc + BYTE_LENGTH;
    let store_val = reader.get_byte(pc)?;

    if operands.len() < 2 {
        return Err(ZmachineError::InstructionsInvalid2OP());
    }

    let op1 = operands[0];
    let op2 = operands[1];

    match opcode {
        0x01..=0x07 => handle_branch_instruction(pc, opcode, operands, reader, version, verbosity),
        0x08 => zor(store_pc, op1, op2, store_val, verbosity),
        0x09 => zand(store_pc, op1, op2, store_val, verbosity),
        0x0a => handle_branch_instruction(pc, opcode, operands, reader, version, verbosity),
        0x0b => set_attr(pc, op1, op2, verbosity),
        0x0c => clear_attr(pc, op1, op2, verbosity),
        0x0d => store(pc, op1, op2, verbosity),
        0x0e => insert_obj(pc, op1, op2, verbosity),
        0x0f => loadw(store_pc, reader, op1, op2, store_val, verbosity),
        0x10 => loadb(store_pc, reader, op1, op2, store_val, verbosity),
        // All the instructions below this take a store variable, which is the byte at the pc
        0x11 => get_prop(store_pc, op1, op2, store_val, reader, verbosity),
        0x12 => get_prop_addr(store_pc, op1, op2, store_val, reader, verbosity),
        0x13 => get_next_prop(store_pc, op1, op2, store_val, reader, verbosity),
        0x14 => add(store_pc, op1, op2, store_val, verbosity),
        0x15 => subtract(store_pc, op1, op2, store_val, verbosity),
        0x16 => mul(store_pc, op1, op2, store_val, verbosity),
        0x17 => div(store_pc, op1, op2, store_val, verbosity),
        0x18 => zmod(store_pc, op1, op2, store_val, verbosity),
        _ => {
            println!("Unhandled 2OP instruction with opcode 0x{:02X}", opcode);
            Err(ZmachineError::InstructionsUnhandledInstruction(opcode))
        }
    }
}

///
/// Handles subset of instructions that involve branching _and_ storing
///
pub fn handle_branch_and_store_instruction<T: MemoryReader + ObjectTreeReader>(
    pc: usize,
    opcode: u8,
    operand: Operand,
    store_val: u8,
    reader: &mut T,
    _version: ZCodeVersion,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let mut final_pc = pc;

    let branch_byte = reader.get_byte(final_pc)?;
    final_pc += BYTE_LENGTH;

    // Bit 7 indicates whether to branch on true or false
    let branch_on_true = (branch_byte & 0x80) > 0;

    // Bit 6 indicates whether this is a one or two byte offset
    let offset = if (branch_byte & 0x40) > 0 {
        (branch_byte & 0x3f) as u16 // Bottom 6 bits have offset
    } else {
        let second_branch_byte = reader.get_byte(final_pc)?;
        final_pc += BYTE_LENGTH;
        // Bottom 14 bytes of entire word has offset, as signed
        (((branch_byte & 0x3f) as u16) << 8) | (second_branch_byte as u16)
    };

    // 0 and 1 are treated as returns, so should pass through directly
    let branch_addr = match offset {
        0 => 0,
        1 => 1,
        _ => (final_pc as i32 + word_to_signed_14bit(offset) as i32 - 2) as usize,
    };

    match opcode {
        0x01 => get_sibling(
            final_pc,
            operand,
            store_val,
            reader,
            branch_addr,
            branch_on_true,
            verbosity,
        ),
        0x02 => get_child(
            final_pc,
            operand,
            store_val,
            reader,
            branch_addr,
            branch_on_true,
            verbosity,
        ),
        _ => Err(ZmachineError::InstructionsUnhandledInstruction(opcode)),
    }
}

///
/// Handles the subset of instructions that involve branching.
/// See Section 4.7
///
pub fn handle_branch_instruction<T: MemoryReader + ObjectTreeReader>(
    pc: usize,
    opcode: u8,
    operands: Vec<Operand>,
    reader: &mut T,
    version: ZCodeVersion,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let mut final_pc = pc;

    let branch_byte = reader.get_byte(final_pc)?;
    final_pc += BYTE_LENGTH;

    // Bit 7 indicates whether to branch on true or false
    let branch_on_true = (branch_byte & 0x80) > 0;

    // Bit 6 indicates whether this is a one or two byte offset
    let offset = if (branch_byte & 0x40) > 0 {
        (branch_byte & 0x3f) as u16 // Bottom 6 bits have offset
    } else {
        let second_branch_byte = reader.get_byte(final_pc)?;
        final_pc += BYTE_LENGTH;
        // Bottom 14 bytes of entire word has offset, as signed
        (((branch_byte & 0x3f) as u16) << 8) | (second_branch_byte as u16)
    };

    // 0 and 1 are treated as returns, so should pass through directly
    let branch_addr = match offset {
        0 => 0,
        1 => 1,
        _ => (final_pc as i32 + word_to_signed_14bit(offset) as i32 - 2) as usize,
    };

    match opcode {
        0x00 => jz(
            final_pc,
            operands[0],
            branch_addr,
            branch_on_true,
            verbosity,
        ), // the only 1-op branch
        0x01 => je(final_pc, operands, branch_addr, branch_on_true, verbosity),
        0x02 => jl(
            final_pc,
            operands[0],
            operands[1],
            branch_addr,
            branch_on_true,
            verbosity,
        ),
        0x03 => jg(
            final_pc,
            operands[0],
            operands[1],
            branch_addr,
            branch_on_true,
            verbosity,
        ),
        0x04 => dec_chk(
            final_pc,
            operands,
            reader,
            branch_addr,
            branch_on_true,
            verbosity,
        ),
        0x05 => inc_chk(
            final_pc,
            operands,
            reader,
            branch_addr,
            branch_on_true,
            verbosity,
        ),
        0x06 => jin(
            final_pc,
            operands[0],
            operands[1],
            reader,
            branch_addr,
            branch_on_true,
            verbosity,
        ),
        0x07 => ztest(
            final_pc,
            operands[0],
            operands[1],
            branch_addr,
            branch_on_true,
            verbosity,
        ),
        0x0a => test_attr(
            final_pc,
            operands[0],
            operands[1],
            reader,
            branch_addr,
            branch_on_true,
            verbosity,
        ),
        0x0d => verify(final_pc, reader, branch_addr, branch_on_true, verbosity),
        // Not the real opcode, the handle_0op will convert save/restore to this so the
        // branch logic can be used
        SAVE_PLACEHOLDER_OPCODE => save(final_pc, branch_addr, branch_on_true, verbosity, version),
        RESTORE_PLACEHOLDER_OPCODE => {
            restore(final_pc, branch_addr, branch_on_true, verbosity, version)
        }
        _ => Err(ZmachineError::InstructionsUnhandledInstruction(opcode)),
    }
}

#[test]
fn test_2op_jump_mappings() -> Result<(), ZmachineError> {
    // Padded with 2 empty bytes so we can test offset and compare it with absolute
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x00, 0x00, 0x03, 0x05, 0x05, 0x80, 0xbe,
    ]);

    let (_, msg) = handle_instruction(2, &mut reader, ZCodeVersion::V3, DebugVerbosity::All)
        .expect("error handling");
    let raw_msg = msg.unwrap();
    assert_eq!("jg 0x05 0x05 [TRUE] 0x0000C3", raw_msg);

    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x00, 0x00, 0xc3, 0x0f, 0xff, 0x12, 0x34, 0xff, 0x00, 0x98,
    ]);

    let (_, msg) = handle_instruction(2, &mut reader, ZCodeVersion::V3, DebugVerbosity::All)
        .expect("error handling");
    let raw_msg = msg.unwrap();
    assert_eq!("jg 0xFF12 0x34FF [FALSE] 0x0000A0", raw_msg);

    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x00, 0x78, 0x3f, 0xfa,
    ]);

    let (_, msg) = handle_instruction(6, &mut reader, ZCodeVersion::V3, DebugVerbosity::All)
        .expect("error handling");
    let raw_msg = msg.unwrap();
    assert_eq!("jg (SP) 0x78 [FALSE] 0x000003", raw_msg);

    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x00, 0x00, 0x00, 0x00, 0x43, 0x00, 0x78, 0x00, 0x00,
    ]);

    let (_, msg) = handle_instruction(4, &mut reader, ZCodeVersion::V3, DebugVerbosity::All)
        .expect("error handling");
    let raw_msg = msg.unwrap();
    assert_eq!("jg (SP) 0x78 [FALSE] R0", raw_msg);

    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x00, 0x00, 0x00, 0x00, 0x43, 0x00, 0x78, 0x40,
    ]);

    let (_, msg) = handle_instruction(4, &mut reader, ZCodeVersion::V3, DebugVerbosity::All)
        .expect("error handling");
    let raw_msg = msg.unwrap();
    assert_eq!("jg (SP) 0x78 [FALSE] R0", raw_msg);

    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x00, 0x00, 0x00, 0x00, 0x43, 0x00, 0x78, 0x00, 0x01,
    ]);

    let (_, msg) = handle_instruction(4, &mut reader, ZCodeVersion::V3, DebugVerbosity::All)
        .expect("error handling");
    let raw_msg = msg.unwrap();
    assert_eq!("jg (SP) 0x78 [FALSE] R1", raw_msg);
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x00, 0x00, 0x00, 0x00, 0x43, 0x00, 0x78, 0x41,
    ]);

    let (_, msg) = handle_instruction(4, &mut reader, ZCodeVersion::V3, DebugVerbosity::All)
        .expect("error handling");
    let raw_msg = msg.unwrap();
    assert_eq!("jg (SP) 0x78 [FALSE] R1", raw_msg);

    Ok(())
}

pub fn handle_var<T: MemoryReader + ObjectTreeReader>(
    pc: usize,
    opcode: u8,
    reader: &mut T,
    version: ZCodeVersion,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let (pc, operands) = extract_operands_var(pc, reader)?;
    let store_pc = pc + BYTE_LENGTH;
    let store_val = reader.get_byte(pc)?;

    match opcode {
        0x00 => match version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                call(pc, reader, operands, verbosity)
            }
        },
        0x01 => storew(pc, operands, verbosity),
        0x02 => storeb(pc, operands, verbosity),
        0x03 => put_prop(pc, operands[0], operands[1], operands[2], reader, verbosity),
        0x04 => match version {
            ZCodeVersion::V1 | ZCodeVersion::V2 | ZCodeVersion::V3 => {
                sread(pc, reader, operands, verbosity)
            }
        },
        0x05 => print_char(pc, operands[0], verbosity),
        0x06 => print_num(pc, operands, verbosity),
        0x07 => zrandom(store_pc, operands[0], store_val, verbosity),
        0x08 => push(pc, operands, verbosity),
        0x09 => pull(pc, operands, reader, verbosity, version),
        0x0A => split_window(pc, operands[0], verbosity),
        0x0B => set_window(pc, operands[0], verbosity),
        0x14 => input_stream(pc, operands[0], verbosity, version),
        0x13 => output_stream(pc, operands, verbosity, version),
        0x15 => sound_effect(pc, operands, verbosity, version),
        _ => {
            println!("Unhandled Var instruction with opcode 0x{:02X}", opcode);
            Err(ZmachineError::InstructionsUnhandledInstruction(opcode))
        }
    }
}

fn extract_operands_var<T: MemoryReader>(
    pc_address: usize,
    reader: &mut T,
) -> Result<(usize, Vec<Operand>), ZmachineError> {
    let operand_type_byte = reader.get_byte(pc_address)?;
    let mut operand_types: [OperandType; 4] = [
        OperandType::Omitted,
        OperandType::Omitted,
        OperandType::Omitted,
        OperandType::Omitted,
    ];

    // The operand type byte describe the number and types of operands, encoded in 2 bits each
    // The highest bits are for the first argument, etc
    //  See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect04.html>, section 4.2
    // The shift Var is used as part of the byte calculations, so an iterator would be redundant
    #[allow(clippy::needless_range_loop)]
    for shift in 0..4 {
        operand_types[shift] = match operand_type_byte >> ((3 - shift) * 2) & 0x03 {
            0 => OperandType::Large,
            1 => OperandType::Small,
            2 => OperandType::Variable,
            _ => OperandType::Omitted,
        };
    }

    extract_operands(pc_address + BYTE_LENGTH, reader, operand_types.to_vec())
}

#[test]
fn test_extract_operands_var() -> Result<(), ZmachineError> {
    // One large
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![0x3f, 0x02, 0x4f, 0xff]);
    assert_eq!(
        (
            3,
            vec![Operand {
                operand_value: 0x024f,
                operand_type: OperandType::Large,
                variable_number: 0
            }]
        ),
        extract_operands_var(0, &mut reader)?
    );

    // Two large
    let mut reader =
        StubV123MemoryObjectReader::create_with_memory(vec![0x0f, 0x02, 0x4f, 0x12, 0x34, 0x00]);
    assert_eq!(
        (
            5,
            vec![
                Operand {
                    operand_value: 0x024f,
                    operand_type: OperandType::Large,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x1234,
                    operand_type: OperandType::Large,
                    variable_number: 0
                }
            ]
        ),
        extract_operands_var(0, &mut reader)?
    );

    // Three large
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x03, 0x11, 0x11, 0x12, 0x34, 0x56, 0x78, 0x01,
    ]);

    assert_eq!(
        (
            7,
            vec![
                Operand {
                    operand_value: 0x1111,
                    operand_type: OperandType::Large,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x1234,
                    operand_type: OperandType::Large,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x5678,
                    operand_type: OperandType::Large,
                    variable_number: 0
                }
            ]
        ),
        extract_operands_var(0, &mut reader)?
    );

    // Four large
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x00, 0x11, 0x11, 0x12, 0x34, 0x56, 0x78, 0xff, 0xff, 0x01,
    ]);
    assert_eq!(
        (
            9,
            vec![
                Operand {
                    operand_value: 0x1111,
                    operand_type: OperandType::Large,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x1234,
                    operand_type: OperandType::Large,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x5678,
                    operand_type: OperandType::Large,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0xffff,
                    operand_type: OperandType::Large,
                    variable_number: 0
                }
            ]
        ),
        extract_operands_var(0, &mut reader)?
    );

    // One large, one small
    let mut reader =
        StubV123MemoryObjectReader::create_with_memory(vec![0x1f, 0x02, 0x4f, 0x12, 0x00]);
    assert_eq!(
        (
            4,
            vec![
                Operand {
                    operand_value: 0x024f,
                    operand_type: OperandType::Large,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x12,
                    operand_type: OperandType::Small,
                    variable_number: 0
                }
            ]
        ),
        extract_operands_var(0, &mut reader)?
    );

    // One large, two small
    let mut reader =
        StubV123MemoryObjectReader::create_with_memory(vec![0x17, 0x11, 0x11, 0x12, 0x34, 0x01]);
    assert_eq!(
        (
            5,
            vec![
                Operand {
                    operand_value: 0x1111,
                    operand_type: OperandType::Large,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x12,
                    operand_type: OperandType::Small,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x34,
                    operand_type: OperandType::Small,
                    variable_number: 0
                }
            ]
        ),
        extract_operands_var(0, &mut reader)?
    );

    // One large, three small
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x015, 0x11, 0x11, 0x12, 0x34, 0x56, 0x01,
    ]);
    assert_eq!(
        (
            6,
            vec![
                Operand {
                    operand_value: 0x1111,
                    operand_type: OperandType::Large,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x12,
                    operand_type: OperandType::Small,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x34,
                    operand_type: OperandType::Small,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x56,
                    operand_type: OperandType::Small,
                    variable_number: 0
                }
            ]
        ),
        extract_operands_var(0, &mut reader)?
    );

    // Large, Small, Large, Small
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x11, 0x11, 0x11, 0x12, 0x34, 0x56, 0x78, 0x01,
    ]);
    assert_eq!(
        (
            7,
            vec![
                Operand {
                    operand_value: 0x1111,
                    operand_type: OperandType::Large,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x12,
                    operand_type: OperandType::Small,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x3456,
                    operand_type: OperandType::Large,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x78,
                    operand_type: OperandType::Small,
                    variable_number: 0
                }
            ]
        ),
        extract_operands_var(0, &mut reader)?
    );

    // Onne large, three Var
    let mut reader = StubV123MemoryObjectReader::create_with_memory_and_variables(
        vec![0x2A, 0x11, 0x11, 0x10, 0x11, 0x12, 0x00],
        vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 0, 0, 0,
        ],
    );
    assert_eq!(
        (
            6,
            vec![
                Operand {
                    operand_value: 0x1111,
                    operand_type: OperandType::Large,
                    variable_number: 0
                },
                Operand {
                    operand_value: 1,
                    operand_type: OperandType::Variable,
                    variable_number: 0x10,
                },
                Operand {
                    operand_value: 2,
                    operand_type: OperandType::Variable,
                    variable_number: 0x11,
                },
                Operand {
                    operand_value: 3,
                    operand_type: OperandType::Variable,
                    variable_number: 0x12,
                }
            ]
        ),
        extract_operands_var(0, &mut reader)?
    );

    Ok(())
}

///
/// Extract the operands for a instruction. Address should be right after the opcode.
///
fn extract_operands<T: MemoryReader>(
    pc_address: usize,
    reader: &mut T,
    operand_types: Vec<OperandType>,
) -> Result<(usize, Vec<Operand>), ZmachineError> {
    let mut operands: Vec<Operand> = Vec::new();
    // print!("EXTRACT : {:?} {:06X}", operand_types, pc_address);
    let mut pc = pc_address;
    // The operands then follow
    for operand_type in operand_types {
        match operand_type {
            OperandType::Large => {
                let v = reader.get_word(pc)?;
                //print!(", LARGE {:04X}", v);
                operands.push(Operand {
                    operand_type: OperandType::Large,
                    operand_value: v,
                    variable_number: 0,
                });
                pc += WORD_LENGTH;
            }
            OperandType::Small => {
                let v = reader.get_byte(pc)? as u16;
                //print!(", SMALL {:04X}", v);
                operands.push(Operand {
                    operand_type: OperandType::Small,
                    operand_value: v,
                    variable_number: 0,
                });
                pc += BYTE_LENGTH;
            }
            OperandType::Variable => {
                let variable = reader.get_byte(pc)? as u8;
                let var_val = reader.get_variable(variable)?;
                // print!(", Var {:04X} = {:04X}", variable, var_val);
                operands.push(Operand {
                    operand_type: OperandType::Variable,
                    operand_value: var_val,
                    variable_number: variable,
                });
                pc += BYTE_LENGTH;
            }
            OperandType::Omitted => {
                // See 4.4.3 -- once a type is given as omitted, all subsequent are as well
                break;
            }
        }
    }
    //println!("");

    Ok((pc, operands))
}

///
/// These functions are all implementations of the instructions. The method sig varies based on what is needed.
/// Some are prefixed by z to avoid clashing with pre-existing symbols
///

///
/// Store the value in operand 2 into variable specified in operand 1
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#store
///
pub fn store(
    pc_address: usize,
    var_op: Operand,
    val_op: Operand,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    if var_op.operand_value > 255 {
        return Err(ZmachineError::InstructionsOperandVariableOutOfBounds(
            var_op.operand_value,
        ));
    }

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("store", &[var_op, val_op])),
    };

    Ok((
        Action::StoreVariable(
            var_op.operand_value as u8,
            val_op.operand_value,
            pc_address,
            true,
        ),
        instruction_text,
    ))
}

#[test]
fn test_store() -> Result<(), ZmachineError> {
    assert_eq!(
        (Action::StoreVariable(1, 2, 0, true), None),
        store(
            0,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x02,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            DebugVerbosity::None
        )
        .expect("Error in store")
    );

    assert_eq!(
        Err(ZmachineError::InstructionsOperandVariableOutOfBounds(
            0x01f1
        )),
        store(
            0,
            Operand {
                operand_value: 0x01f1,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            Operand {
                operand_value: 0x02,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Push a value onto the stack
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#push
///
pub fn push(
    pc_address: usize,
    operands: Vec<Operand>,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    if operands.len() != 1 {
        return Err(ZmachineError::InstructionsExpected1Operand());
    }

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("push", &operands)),
    };

    Ok((
        Action::StoreVariable(0, operands[0].operand_value, pc_address, false),
        instruction_text,
    ))
}

#[test]
fn test_push() -> Result<(), ZmachineError> {
    assert_eq!(
        (Action::StoreVariable(0, 1, 4, false), None),
        push(
            4,
            vec![Operand {
                operand_value: 0x01,
                operand_type: OperandType::Large,
                variable_number: 0,
            },],
            DebugVerbosity::None
        )
        .expect("Error in push")
    );

    assert_eq!(
        Err(ZmachineError::InstructionsExpected1Operand()),
        push(
            4,
            vec![
                Operand {
                    operand_value: 0x01,
                    operand_type: OperandType::Large,
                    variable_number: 0,
                },
                Operand {
                    operand_value: 0x01,
                    operand_type: OperandType::Large,
                    variable_number: 0,
                },
            ],
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Pop the stack and discard the value
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#pop
///
pub fn pop(
    pc_address: usize,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some("pop".to_string()),
    };

    Ok((Action::Pop(pc_address), instruction_text))
}

#[test]
fn test_pop() -> Result<(), ZmachineError> {
    assert_eq!(
        (Action::Pop(4), None),
        pop(4, DebugVerbosity::None,).expect("Error in pop")
    );

    Ok(())
}

///
/// Pop a value from the stack into another variable
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#pull
///
pub fn pull<T: MemoryReader>(
    pc_address: usize,
    operands: Vec<Operand>,
    reader: &mut T,
    verbosity: DebugVerbosity,
    _version: ZCodeVersion,
) -> Result<(Action, Option<String>), ZmachineError> {
    if operands.len() != 1 {
        return Err(ZmachineError::InstructionsExpected1Operand());
    }

    let variable_number = operands[0].operand_value;
    if variable_number > 255 {
        return Err(ZmachineError::InstructionsOperandVariableOutOfBounds(
            variable_number,
        ));
    }

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("pull", &operands)),
    };

    if variable_number == 0 {
        // 6.3.4
        // Had to look at the "@pull sp" tests in czech to figure this out
        // Pull with the SP means to take the _top_ object on the stack, then
        // _replace_ the next object on the stack with it
        Ok((
            Action::StoreVariable(0, reader.get_variable(0)?, pc_address, true),
            instruction_text,
        ))
    } else {
        Ok((
            Action::PopAndStore(variable_number as u8, pc_address),
            instruction_text,
        ))
    }
}

#[test]
fn test_pull() -> Result<(), ZmachineError> {
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x11, 0x11, 0x11, 0x12, 0x34, 0x56, 0x78, 0x01,
    ]);
    assert_eq!(
        (Action::PopAndStore(1, 4), None),
        pull(
            4,
            vec![Operand {
                operand_value: 0x01,
                operand_type: OperandType::Large,
                variable_number: 0,
            },],
            &mut reader,
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
        .expect("Error in pull")
    );

    assert_eq!(
        Err(ZmachineError::InstructionsOperandVariableOutOfBounds(0x1ff)),
        pull(
            4,
            vec![Operand {
                operand_value: 0x1ff,
                operand_type: OperandType::Large,
                variable_number: 0,
            }],
            &mut reader,
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    assert_eq!(
        Err(ZmachineError::InstructionsExpected1Operand()),
        pull(
            4,
            vec![
                Operand {
                    operand_value: 0x01,
                    operand_type: OperandType::Large,
                    variable_number: 0,
                },
                Operand {
                    operand_value: 0x01,
                    operand_type: OperandType::Large,
                    variable_number: 0,
                },
            ],
            &mut reader,
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    Ok(())
}

///
/// Store a byte value into an address
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#storeb
///
pub fn storeb(
    pc_address: usize,
    operands: Vec<Operand>,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    if operands.len() != 3 {
        return Err(ZmachineError::InstructionsExpected3Operands());
    }

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("storeb", &operands)),
    };

    Ok((
        Action::StoreByte(
            operands[0].operand_value as usize + operands[1].operand_value as usize,
            operands[2].operand_value as u8,
            pc_address,
        ),
        instruction_text,
    ))
}

#[test]
fn test_storeb() -> Result<(), ZmachineError> {
    let operands = vec![
        Operand {
            operand_value: 0x01,
            operand_type: OperandType::Large,
            variable_number: 0,
        },
        Operand {
            operand_value: 0x02,
            operand_type: OperandType::Large,
            variable_number: 0,
        },
        Operand {
            operand_value: 0x04,
            operand_type: OperandType::Large,
            variable_number: 0,
        },
    ];

    assert_eq!(
        (Action::StoreByte(3, 4, 4), None),
        storeb(4, operands, DebugVerbosity::None).expect("Error in storeb")
    );

    let operands = vec![Operand {
        operand_value: 0x01,
        operand_type: OperandType::Large,
        variable_number: 0,
    }];
    assert_eq!(
        Err(ZmachineError::InstructionsExpected3Operands()),
        storeb(4, operands, DebugVerbosity::None)
    );

    Ok(())
}

///
/// Store a word value into an address
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#storew
///
pub fn storew(
    pc_address: usize,
    operands: Vec<Operand>,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    if operands.len() != 3 {
        return Err(ZmachineError::InstructionsExpected3Operands());
    }

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("storew", &operands)),
    };

    Ok((
        Action::StoreWord(
            operands[0].operand_value as usize + (WORD_LENGTH * operands[1].operand_value as usize),
            operands[2].operand_value,
            pc_address,
        ),
        instruction_text,
    ))
}

#[test]
fn test_storew() -> Result<(), ZmachineError> {
    let operands = vec![
        Operand {
            operand_value: 0x01,
            operand_type: OperandType::Large,
            variable_number: 0,
        },
        Operand {
            operand_value: 0x02,
            operand_type: OperandType::Large,
            variable_number: 0,
        },
        Operand {
            operand_value: 0x04,
            operand_type: OperandType::Large,
            variable_number: 0,
        },
    ];
    assert_eq!(
        (Action::StoreWord(5, 4, 4), None),
        storew(4, operands, DebugVerbosity::None).expect("Error in storew")
    );

    let operands = vec![Operand {
        operand_value: 0x01,
        operand_type: OperandType::Large,
        variable_number: 0,
    }];

    assert_eq!(
        Err(ZmachineError::InstructionsExpected3Operands()),
        storew(0, operands, DebugVerbosity::None)
    );

    Ok(())
}

///
/// Load a variable into another variable
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#load
///

pub fn load<T: MemoryReader>(
    pc_address: usize,
    reader: &mut T,
    var_op: Operand,
    variable_number: u8,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    if var_op.operand_value > 255 {
        return Err(ZmachineError::InstructionsOperandVariableOutOfBounds(
            var_op.operand_value,
        ));
    }

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_store(
            "load",
            &[var_op],
            variable_number,
        )),
    };

    Ok((
        Action::StoreVariable(
            variable_number,
            reader.peek_variable(var_op.operand_value as u8, false)?,
            pc_address,
            false,
        ),
        instruction_text,
    ))
}

#[test]
fn test_zload() -> Result<(), ZmachineError> {
    let mut reader = StubV123MemoryObjectReader::create_with_memory_and_variables(
        vec![0xff, 0x00, 0x00, 0xcc, 0xee],
        vec![0xcc; 256],
    );

    assert_eq!(
        (Action::StoreVariable(0xff, 0xcc, 1, false), None),
        load(
            1,
            &mut reader,
            Operand {
                operand_value: 0xff,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            0xff,
            DebugVerbosity::None
        )
        .expect("Error in load")
    );

    assert_eq!(
        Err(ZmachineError::InstructionsOperandVariableOutOfBounds(0x1ff)),
        load(
            1,
            &mut reader,
            Operand {
                operand_value: 0x1ff,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            0xff,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Load a byte into a variable
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#loadb
///

pub fn loadb<T: MemoryReader>(
    pc_address: usize,
    reader: &mut T,
    addr_op: Operand,
    offset_op: Operand,
    variable_number: u8,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let b = reader
        .get_byte_bounds_check(addr_op.operand_value as usize + offset_op.operand_value as usize)?;

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_store(
            "loadb",
            &[addr_op, offset_op],
            variable_number,
        )),
    };

    Ok((
        Action::StoreVariable(variable_number, b as u16, pc_address, false),
        instruction_text,
    ))
}

#[test]
fn test_loadb() -> Result<(), ZmachineError> {
    let mut reader =
        StubV123MemoryObjectReader::create_with_memory(vec![0xff, 0x00, 0x00, 0xcc, 0xee]);

    assert_eq!(
        (Action::StoreVariable(0xff, 0xcc, 1, false), None),
        loadb(
            1,
            &mut reader,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            Operand {
                operand_value: 0x02,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            0xff,
            DebugVerbosity::None
        )
        .expect("Error in loadb")
    );

    assert_eq!(
        (Action::StoreVariable(0xff, 0xcc, 1, false), None),
        loadb(
            1,
            &mut reader,
            Operand {
                operand_value: 0x02,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            0xff,
            DebugVerbosity::None
        )
        .expect("Error in loadb")
    );

    assert_eq!(
        (Action::StoreVariable(0xff, 0xee, 1, false), None),
        loadb(
            1,
            &mut reader,
            Operand {
                operand_value: 0x02,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            Operand {
                operand_value: 0x02,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            0xff,
            DebugVerbosity::None
        )
        .expect("Error in loadb")
    );

    Ok(())
}

///
/// Load a word into a variable
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#loadw
///

pub fn loadw<T: MemoryReader>(
    pc_address: usize,
    reader: &mut T,
    addr_op: Operand,
    offset_op: Operand,
    variable_number: u8,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let b = reader.get_word_bounds_check(
        (addr_op.operand_value as i16
            + (WORD_LENGTH as i16 * word_to_signed(offset_op.operand_value))) as usize,
    )?;

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_store(
            "loadw",
            &[addr_op, offset_op],
            variable_number,
        )),
    };
    Ok((
        Action::StoreVariable(variable_number, b as u16, pc_address, false),
        instruction_text,
    ))
}

#[test]
fn test_loadw() -> Result<(), ZmachineError> {
    let mut reader =
        StubV123MemoryObjectReader::create_with_memory(vec![0xff, 0x12, 0x34, 0x56, 0x78]);

    assert_eq!(
        (Action::StoreVariable(0xff, 0x1234, 1, false), None),
        loadw(
            1,
            &mut reader,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            0xff,
            DebugVerbosity::None
        )
        .expect("Error in loadw")
    );

    assert_eq!(
        (Action::StoreVariable(0xff, 0x5678, 1, false), None),
        loadw(
            1,
            &mut reader,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            0xff,
            DebugVerbosity::None
        )
        .expect("Error in loadw")
    );

    assert_eq!(
        (Action::StoreVariable(0xff, 0x5678, 1, false), None),
        loadw(
            1,
            &mut reader,
            Operand {
                operand_value: 0x03,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            0xff,
            DebugVerbosity::None
        )
        .expect("Error in loadw")
    );

    Ok(())
}

///
/// Print a newline
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#newline>
///
pub fn new_line(
    pc_addr: usize,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(String::from("new_line")),
    };

    Ok((
        Action::PrintString(String::from("\n"), pc_addr),
        instruction_text,
    ))
}

#[test]
fn test_new_line() -> Result<(), ZmachineError> {
    assert_eq!(
        (Action::PrintString(String::from("\n"), 0xf1), None),
        new_line(0xf1, DebugVerbosity::None)?
    );
    Ok(())
}

///
/// Show the status
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#show_status>
///
pub fn show_status(
    pc_addr: usize,
    verbosity: DebugVerbosity,
    version: ZCodeVersion,
) -> Result<(Action, Option<String>), ZmachineError> {
    if version != ZCodeVersion::V3 {
        return Err(ZmachineError::InstructionVersionMismatch());
    }
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(String::from("show_status")),
    };

    Ok((Action::ShowStatus(pc_addr), instruction_text))
}

#[test]
fn test_show_status() -> Result<(), ZmachineError> {
    assert_eq!(
        (Action::ShowStatus(0xf1), None),
        show_status(0xf1, DebugVerbosity::None, ZCodeVersion::V3)?
    );
    assert_eq!(
        Err(ZmachineError::InstructionVersionMismatch()),
        show_status(0xf1, DebugVerbosity::None, ZCodeVersion::V1)
    );
    assert_eq!(
        Err(ZmachineError::InstructionVersionMismatch()),
        show_status(0xf1, DebugVerbosity::None, ZCodeVersion::V2)
    );
    Ok(())
}

///
/// Print the string located right after the first byte.
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#print>
///  
pub fn zprint(
    str_addr: usize,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(String::from("print")),
    };

    Ok((
        Action::PrintAddress(str_addr, 0, false, false),
        instruction_text,
    ))
}

#[test]
fn test_zprint() -> Result<(), ZmachineError> {
    assert_eq!(
        (Action::PrintAddress(0xf1, 0, false, false), None),
        zprint(0xf1, DebugVerbosity::None)?
    );
    Ok(())
}

///
/// Print the string located right after the first byte, then return 0
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#print_ret>
///  
pub fn zprint_ret(
    str_addr: usize,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(String::from("print_ret")),
    };

    Ok((
        Action::PrintAddress(str_addr, 0, true, true),
        instruction_text,
    ))
}

#[test]
fn test_zprint_ret() -> Result<(), ZmachineError> {
    assert_eq!(
        (Action::PrintAddress(0xf1, 0, true, true), None),
        zprint_ret(0xf1, DebugVerbosity::None)?
    );
    Ok(())
}

///
/// Print the zscii char.
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#print_char>
///  
pub fn print_char(
    pc_addr: usize,
    operand: Operand,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    if operand.operand_value > 1024 {
        Err(ZmachineError::InstructionPrintCharOutOfRange(
            operand.operand_value,
        ))
    } else {
        let instruction_text = match verbosity {
            DebugVerbosity::None => None,
            _ => Some(make_instruction_text("print_char", &[operand])),
        };

        Ok((
            Action::PrintChar(operand.operand_value, pc_addr),
            instruction_text,
        ))
    }
}

#[test]
fn test_print_char() -> Result<(), ZmachineError> {
    assert_eq!(
        (Action::PrintChar(0x22, 0x100), None),
        print_char(0x100, make_large_operand(0x22), DebugVerbosity::None)?
    );
    Ok(())
}

///
/// Print the string at the packed address contained in the first parameter.
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#print_paddr>
///  
pub fn print_paddr<T: MemoryReader>(
    pc_addr: usize,
    operand: Operand,
    reader: &T,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("print_paddr", &[operand])),
    };

    Ok((
        Action::PrintAddress(
            reader.convert_packed_address(operand.operand_value),
            pc_addr,
            false,
            false,
        ),
        instruction_text,
    ))
}

#[test]
fn test_print_paddr() -> Result<(), ZmachineError> {
    let reader = StubV123MemoryObjectReader::create_with_memory(vec![0x3f, 0x02, 0x4f, 0xff]);

    assert_eq!(
        (Action::PrintAddress(0x22, 0x100, false, false), None),
        print_paddr(
            0x100,
            Operand {
                operand_value: 0x11,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            &reader,
            DebugVerbosity::None
        )?
    );
    Ok(())
}

///
/// Print the string at the address (not packed) contained in the first parameter.
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#print_addr>
///  
pub fn print_addr(
    pc_addr: usize,
    operand: Operand,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("print_addr", &[operand])),
    };
    Ok((
        Action::PrintAddress(operand.operand_value as usize, pc_addr, false, false),
        instruction_text,
    ))
}

#[test]
fn test_print_addr() -> Result<(), ZmachineError> {
    assert_eq!(
        (Action::PrintAddress(0x11, 0x100, false, false), None),
        print_addr(
            0x100,
            Operand {
                operand_value: 0x11,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            DebugVerbosity::None
        )?
    );
    Ok(())
}

///
/// Print the provided number, as signed
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#print_num
///
pub fn print_num(
    pc_address: usize,
    operands: Vec<Operand>,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    if operands.len() != 1 {
        return Err(ZmachineError::InstructionsExpected1Operand());
    }

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("print_num", &operands)),
    };

    Ok((
        Action::PrintString(
            format!("{}", word_to_signed(operands[0].operand_value)),
            pc_address,
        ),
        instruction_text,
    ))
}

#[test]
fn test_print_num() -> Result<(), ZmachineError> {
    assert_eq!(
        (Action::PrintString(String::from("1"), 0), None),
        print_num(
            0,
            vec![Operand {
                operand_value: 1,
                operand_type: OperandType::Large,
                variable_number: 0
            }],
            DebugVerbosity::None
        )?
    );

    assert_eq!(
        (Action::PrintString(String::from("3"), 0), None),
        print_num(
            0,
            vec![Operand {
                operand_value: 3,
                operand_type: OperandType::Small,
                variable_number: 0
            }],
            DebugVerbosity::None
        )?
    );

    assert_eq!(
        (Action::PrintString(String::from("-1"), 0), None),
        print_num(
            0,
            vec![Operand {
                operand_value: (MAX_UNSIGNED - 1) as u16,
                operand_type: OperandType::Large,
                variable_number: 0
            }],
            DebugVerbosity::None
        )?
    );

    Ok(())
}

///
/// Return a value from a routine
///
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#rtrue>
///  
///
pub fn ret(
    operand: Operand,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("ret", &[operand])),
    };

    Ok((Action::Return(operand.operand_value), instruction_text))
}

#[test]
fn test_ret() -> Result<(), ZmachineError> {
    assert_eq!(
        (Action::Return(0xcc), None),
        ret(
            Operand {
                operand_value: 0xcc,
                operand_type: OperandType::Large,
                variable_number: 0
            },
            DebugVerbosity::None
        )?
    );

    Ok(())
}

///
/// Return a popped stack from routine
///
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#rtrue>
///  
///
///

pub fn ret_popped<T: MemoryReader>(
    reader: &mut T,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(String::from("ret_popped")),
    };

    let val = reader.get_variable(0)?;
    Ok((Action::Return(val), instruction_text))
}

#[test]
fn test_ret_popped() -> Result<(), ZmachineError> {
    let mut reader = StubV123MemoryObjectReader::create_with_memory_and_variables(
        vec![0x3f, 0x02, 0x4f, 0xff],
        vec![0xff; 255],
    );

    assert_eq!(
        (Action::Return(0xff), None),
        ret_popped(&mut reader, DebugVerbosity::None)?
    );

    Ok(())
}

///
/// Return TRUE from a routine
///
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#rtrue>
///  
pub fn rtrue(verbosity: DebugVerbosity) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(String::from("rtrue")),
    };

    Ok((Action::Return(ZMACHINE_TRUE), instruction_text))
}

#[test]
fn test_rtrue() -> Result<(), ZmachineError> {
    assert_eq!(
        (Action::Return(ZMACHINE_TRUE), None),
        rtrue(DebugVerbosity::None)?
    );
    Ok(())
}

///
/// Return FALSE from a routine
///
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#rfalse>
///  
pub fn rfalse(verbosity: DebugVerbosity) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(String::from("rfalse")),
    };

    Ok((Action::Return(ZMACHINE_FALSE), instruction_text))
}

#[test]
fn test_rfalse() -> Result<(), ZmachineError> {
    assert_eq!(
        (Action::Return(ZMACHINE_FALSE), None),
        rfalse(DebugVerbosity::None)?
    );
    Ok(())
}

///
/// QUIT the interpreter
///
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#quit>
///  
pub fn zquit(verbosity: DebugVerbosity) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(String::from("quit")),
    };

    Ok((Action::Quit(), instruction_text))
}

#[test]
fn test_zquit() -> Result<(), ZmachineError> {
    assert_eq!((Action::Quit(), None), zquit(DebugVerbosity::None)?);
    Ok(())
}

///
/// CALL a function. Will have 1-4 arguments.
///
/// The first argument is the address.
///
/// For V1-3: The next (optional) 0-3 are initial values for local variables
///
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#call>
///  
pub fn call<T: MemoryReader>(
    pc_address: usize,
    reader: &mut T,
    operands: Vec<Operand>,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    if operands.is_empty() {
        return Err(ZmachineError::InstructionMissingAddress());
    }

    let return_var = reader.get_byte(pc_address)?;
    let argument_count = operands.len();
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => {
            let mut s = String::from("call");
            for (idx, operand) in operands.iter().enumerate() {
                s.push(' ');
                if idx != 0 {
                    s.push_str(format_operand(*operand).as_str());
                } else {
                    s.push_str(
                        format!(
                            "{:06X}",
                            reader.convert_packed_address(operand.operand_value)
                        )
                        .as_str(),
                    );
                }
            }
            s.push_str(format_return_var(return_var).as_str());
            Some(s)
        }
    };

    // First operand is the address, which is stored as packed address
    Ok((
        Action::Call(
            reader.convert_packed_address(operands[0].operand_value),
            (argument_count - 1) as u8,
            if argument_count > 1 {
                operands[1].operand_value
            } else {
                0
            },
            if argument_count > 2 {
                operands[2].operand_value
            } else {
                0
            },
            if argument_count > 3 {
                operands[3].operand_value
            } else {
                0
            },
            return_var,
            pc_address + BYTE_LENGTH,
        ),
        instruction_text,
    ))
}

#[test]
fn test_call() -> Result<(), ZmachineError> {
    // Expect first argument to always be large (packed address of routine)
    // Then 0-3
    // Each can be small, large, variable
    // This test is also testing Var-type instruction behavior

    // No arguments, return variable 0xff
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![0x3f, 0x02, 0x4f, 0xff]);
    let (pc, operands) = extract_operands_var(0, &mut reader)?;
    assert_eq!(
        (Action::Call(0x049e, 0, 0, 0, 0, 0xff, 4), None),
        call(pc, &mut reader, operands, DebugVerbosity::None).expect("Error in extract")
    );

    // One large, return val is stack (0)
    let mut reader =
        StubV123MemoryObjectReader::create_with_memory(vec![0x0f, 0x02, 0x4f, 0x12, 0x34, 0x00]);
    let (pc, operands) = extract_operands_var(0, &mut reader)?;
    assert_eq!(
        (Action::Call(0x049e, 1, 0x1234, 0, 0, 0x00, 6), None),
        call(pc, &mut reader, operands, DebugVerbosity::None).expect("Error in extract")
    );

    // Two large
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x03, 0x11, 0x11, 0x12, 0x34, 0x56, 0x78, 0x01,
    ]);
    let (pc, operands) = extract_operands_var(0, &mut reader)?;
    assert_eq!(
        (Action::Call(0x2222, 2, 0x1234, 0x5678, 0, 0x01, 8), None),
        call(pc, &mut reader, operands, DebugVerbosity::None).expect("Error in extract")
    );

    // Three large
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x00, 0x11, 0x11, 0x12, 0x34, 0x56, 0x78, 0xff, 0xff, 0x01,
    ]);
    let (pc, operands) = extract_operands_var(0, &mut reader)?;
    assert_eq!(
        (
            Action::Call(0x2222, 3, 0x1234, 0x5678, 0xffff, 0x1, 10),
            None
        ),
        call(pc, &mut reader, operands, DebugVerbosity::None).expect("Error in extract")
    );

    // One small (note first Var is still large for address)
    let mut reader =
        StubV123MemoryObjectReader::create_with_memory(vec![0x1f, 0x02, 0x4f, 0x12, 0x00]);
    let (pc, operands) = extract_operands_var(0, &mut reader)?;
    assert_eq!(
        (Action::Call(0x049e, 1, 0x12, 0, 0, 0x00, 5), None),
        call(pc, &mut reader, operands, DebugVerbosity::None).expect("Error in extract")
    );

    // Two small
    let mut reader =
        StubV123MemoryObjectReader::create_with_memory(vec![0x17, 0x11, 0x11, 0x12, 0x34, 0x01]);
    let (pc, operands) = extract_operands_var(0, &mut reader)?;
    assert_eq!(
        (Action::Call(0x2222, 2, 0x12, 0x34, 0, 0x01, 6), None),
        call(pc, &mut reader, operands, DebugVerbosity::None).expect("Error in extract")
    );

    // Three small
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x015, 0x11, 0x11, 0x12, 0x34, 0x56, 0x01,
    ]);
    let (pc, operands) = extract_operands_var(0, &mut reader)?;
    assert_eq!(
        (Action::Call(0x2222, 3, 0x12, 0x34, 0x56, 0x01, 7), None),
        call(pc, &mut reader, operands, DebugVerbosity::None).expect("Error in extract")
    );

    // Small, Large, Small
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x11, 0x11, 0x11, 0x12, 0x34, 0x56, 0x78, 0x01,
    ]);
    let (pc, operands) = extract_operands_var(0, &mut reader)?;
    assert_eq!(
        (Action::Call(0x2222, 3, 0x12, 0x3456, 0x78, 0x01, 8), None),
        call(pc, &mut reader, operands, DebugVerbosity::None).expect("Error in extract")
    );

    // Three Var
    let mut reader = StubV123MemoryObjectReader::create_with_memory_and_variables(
        vec![0x2A, 0x11, 0x11, 0x10, 0x11, 0x12, 0x00],
        vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 0, 0, 0,
        ],
    );
    let (pc, operands) = extract_operands_var(0, &mut reader)?;
    assert_eq!(
        (Action::Call(0x2222, 3, 1, 2, 3, 0x00, 7), None),
        call(pc, &mut reader, operands, DebugVerbosity::None).expect("Error in extract")
    );

    Ok(())
}

///
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#read>
///  
pub fn sread<T: MemoryReader>(
    pc_address: usize,
    reader: &mut T,
    operands: Vec<Operand>,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    if operands.len() != 2 {
        return Err(ZmachineError::InstructionsExpected2Operands());
    }

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("sread", &operands)),
    };

    let char_count = reader.get_byte_bounds_check(operands[0].operand_value as usize)? + 1;

    // First operand is the address, which is stored as packed address
    Ok((
        Action::ReadLine(
            char_count,
            operands[0].operand_value,
            operands[1].operand_value,
            pc_address,
        ),
        instruction_text,
    ))
}

#[test]
fn test_sread() -> Result<(), ZmachineError> {
    // No arguments, return variable 0xff
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x0f, 0x00, 0x05, 0x11, 0x11, 0x01, 0x01,
    ]);
    let (pc, operands) = extract_operands_var(0, &mut reader)?;
    assert_eq!(
        (Action::ReadLine(2, 0x0005, 0x1111, 0x05), None),
        sread(pc, &mut reader, operands, DebugVerbosity::None).expect("Error in extract")
    );

    let mut reader = StubV123MemoryObjectReader::create_with_memory_and_variables(
        vec![0x2A, 0x11, 0x11, 0x10, 0x11, 0x12, 0x00],
        vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 0, 0, 0,
        ],
    );

    let (pc, operands) = extract_operands_var(0, &mut reader)?;
    assert_eq!(
        Err(ZmachineError::InstructionsExpected2Operands()),
        sread(pc, &mut reader, operands, DebugVerbosity::None)
    );

    Ok(())
}

/// Unconditional jump
/// Note not a branch instruction
///
pub fn jump(
    pc_address: usize,
    a: Operand,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let jump_address = (pc_address as i32 + (word_to_signed(a.operand_value) as i32) - 2) as usize;
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_jump("jump", jump_address)),
    };

    Ok((Action::Jump(jump_address), instruction_text))
}

#[test]
fn test_jump() -> Result<(), ZmachineError> {
    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        jump(
            0x100,
            Operand {
                operand_value: 0x02,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x110), None)),
        jump(
            0x100,
            Operand {
                operand_value: 0x12,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0xf8), None)),
        jump(
            0x100,
            Operand {
                operand_value: signed_to_word(-6),
                operand_type: OperandType::Large,
                variable_number: 0
            },
            DebugVerbosity::None
        )
    );

    Ok(())
}

pub fn inc_dec_chk_return(
    instruction_text: Option<String>,
    branch_on_true: bool,
    result: bool,
    variable_number: u8,
    store_val: u16,
    pc_address: usize,
    branch_addr: usize,
) -> Result<(Action, Option<String>), ZmachineError> {
    // Have to duplicate the branch logic in handle_branch since the
    // StoreVariableReturn might need to be used
    let branch = if branch_on_true { result } else { !result };

    let action = if !branch {
        Action::StoreVariable(variable_number, store_val, pc_address, true)
    } else {
        match branch_addr {
            0 => Action::StoreVariableAndReturn(variable_number, store_val, ZMACHINE_FALSE),
            1 => Action::StoreVariableAndReturn(variable_number, store_val, ZMACHINE_TRUE),
            _ => Action::StoreVariable(variable_number, store_val, branch_addr, true),
        }
    };

    Ok((action, instruction_text))
}

#[test]
fn test_inc_dec_chk_return() -> Result<(), ZmachineError> {
    // Test store path
    assert_eq!(
        Ok((Action::StoreVariable(2, 3, 0x1234, true), None)),
        inc_dec_chk_return(None, true, false, 2, 3, 0x1234, 0x4321)
    );

    // Test store, return false
    assert_eq!(
        Ok((Action::StoreVariableAndReturn(2, 3, ZMACHINE_FALSE), None)),
        inc_dec_chk_return(None, true, true, 2, 3, 0x1234, 0)
    );

    // Test store, return true
    assert_eq!(
        Ok((Action::StoreVariableAndReturn(2, 3, ZMACHINE_TRUE), None)),
        inc_dec_chk_return(None, true, true, 2, 3, 0x1234, 1)
    );

    // Test store, don't return
    assert_eq!(
        Ok((Action::StoreVariable(2, 3, 0x4321, true), None)),
        inc_dec_chk_return(None, true, true, 2, 3, 0x1234, 0x4321)
    );

    //
    // With branch on true flipped, behavior inverts
    //
    assert_eq!(
        Ok((Action::StoreVariable(2, 3, 0x1234, true), None)),
        inc_dec_chk_return(None, false, true, 2, 3, 0x1234, 0x4321)
    );

    assert_eq!(
        Ok((Action::StoreVariableAndReturn(2, 3, ZMACHINE_FALSE), None)),
        inc_dec_chk_return(None, false, false, 2, 3, 0x1234, 0)
    );

    assert_eq!(
        Ok((Action::StoreVariableAndReturn(2, 3, ZMACHINE_TRUE), None)),
        inc_dec_chk_return(None, false, false, 2, 3, 0x1234, 1)
    );

    assert_eq!(
        Ok((Action::StoreVariable(2, 3, 0x4321, true), None)),
        inc_dec_chk_return(None, false, false, 2, 3, 0x1234, 0x4321)
    );

    Ok(())
}

///
/// Decrement a, then branch if a < v (signed)
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#dec_chk
///
pub fn dec_chk<T: MemoryReader>(
    pc_address: usize,
    operands: Vec<Operand>,
    reader: &mut T,
    branch_addr: usize,
    branch_on_true: bool,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    if operands.len() < 2 {
        return Err(ZmachineError::InstructionsExpected2Operands());
    }

    if operands[0].operand_value > 255 {
        return Err(ZmachineError::InstructionsOperandVariableOutOfBounds(
            operands[0].operand_value,
        ));
    }

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_branch(
            "dec_chk",
            &operands,
            branch_addr,
            branch_on_true,
        )),
    };

    let variable_number = operands[0].operand_value as u8;
    let new_val = word_to_signed(reader.peek_variable(variable_number, false)?) - 1;
    let result = new_val < word_to_signed(operands[1].operand_value);
    let store_val = signed_to_word(new_val);

    inc_dec_chk_return(
        instruction_text,
        branch_on_true,
        result,
        variable_number,
        store_val,
        pc_address,
        branch_addr,
    )
}

#[test]
fn test_dec_chk() -> Result<(), ZmachineError> {
    let mut reader = StubV123MemoryObjectReader::create_with_memory_and_variables(
        vec![0x0f, 0x00, 0x05, 0x11, 0x11, 0x01, 0x01],
        vec![0; 256],
    );

    assert_eq!(
        Err(ZmachineError::InstructionsExpected2Operands()),
        dec_chk(0x100, vec![], &mut reader, 0x40, true, DebugVerbosity::None)
    );

    assert_eq!(
        Err(ZmachineError::InstructionsExpected2Operands()),
        dec_chk(
            0x100,
            vec![make_small_operand(0x01)],
            &mut reader,
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Err(ZmachineError::InstructionsOperandVariableOutOfBounds(0x1ff)),
        dec_chk(
            0x100,
            vec![make_large_operand(0x1ff), make_small_operand(0x01)],
            &mut reader,
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    reader.set_variable(0xff, 0xfd);

    assert_eq!(
        Ok((Action::StoreVariable(0xff, 0xfc, 0x100, true), None)),
        dec_chk(
            0x100,
            vec![make_small_operand(0xff), make_small_operand(0xfb)],
            &mut reader,
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0xff, 0xfc, 0x40, true), None)),
        dec_chk(
            0x100,
            vec![make_small_operand(0xff), make_small_operand(0xfb)],
            &mut reader,
            0x40,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariableAndReturn(0xff, 0xfc, 0), None)),
        dec_chk(
            0x100,
            vec![make_small_operand(0xff), make_small_operand(0xfb)],
            &mut reader,
            0x00,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariableAndReturn(0xff, 0xfc, 1), None)),
        dec_chk(
            0x100,
            vec![make_small_operand(0xff), make_small_operand(0xfb)],
            &mut reader,
            0x01,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariableAndReturn(0xff, 0xfc, 1), None)),
        dec_chk(
            0x100,
            vec![make_small_operand(0xff), make_small_operand(0xfb)],
            &mut reader,
            0x01,
            false,
            DebugVerbosity::None
        )
    );

    reader.set_variable(0xff, 0x00);

    assert_eq!(
        Ok((Action::StoreVariable(0xff, 65535, 0x100, true), None)),
        dec_chk(
            0x100,
            vec![make_small_operand(0xff), make_small_operand(0xfb)],
            &mut reader,
            0x40,
            false,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Increment a, then branch if a > v (signed)
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#inc_chk
///
pub fn inc_chk<T: MemoryReader>(
    pc_address: usize,
    operands: Vec<Operand>,
    reader: &mut T,
    branch_addr: usize,
    branch_on_true: bool,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    if operands.len() < 2 {
        return Err(ZmachineError::InstructionsExpected2Operands());
    }

    if operands[0].operand_value > 255 {
        return Err(ZmachineError::InstructionsOperandVariableOutOfBounds(
            operands[0].operand_value,
        ));
    }
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_branch(
            "inc_chk",
            &operands,
            branch_addr,
            branch_on_true,
        )),
    };

    let variable_number = operands[0].operand_value as u8;
    let new_val = word_to_signed(reader.peek_variable(variable_number, false)?) + 1;
    let result = new_val > word_to_signed(operands[1].operand_value);
    let store_val = signed_to_word(new_val);

    inc_dec_chk_return(
        instruction_text,
        branch_on_true,
        result,
        variable_number,
        store_val,
        pc_address,
        branch_addr,
    )
}

#[test]
fn test_inc_chk() -> Result<(), ZmachineError> {
    let mut reader = StubV123MemoryObjectReader::create_with_memory_and_variables(
        vec![0x0f, 0x00, 0x05, 0x11, 0x11, 0x01, 0x01],
        vec![0; 256],
    );

    assert_eq!(
        Err(ZmachineError::InstructionsExpected2Operands()),
        inc_chk(0x100, vec![], &mut reader, 0x40, true, DebugVerbosity::None)
    );

    assert_eq!(
        Err(ZmachineError::InstructionsExpected2Operands()),
        inc_chk(
            0x100,
            vec![make_small_operand(0x01)],
            &mut reader,
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Err(ZmachineError::InstructionsOperandVariableOutOfBounds(0x1ff)),
        inc_chk(
            0x100,
            vec![make_large_operand(0x1ff), make_small_operand(0x01)],
            &mut reader,
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    reader.set_variable(0xff, 0xfd);

    assert_eq!(
        Ok((Action::StoreVariable(0xff, 0xfe, 0x100, true), None)),
        inc_chk(
            0x100,
            vec![make_small_operand(0xff), make_small_operand(0xfe)],
            &mut reader,
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0xff, 0xfe, 0x40, true), None)),
        inc_chk(
            0x100,
            vec![make_small_operand(0xff), make_small_operand(0xfe)],
            &mut reader,
            0x40,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariableAndReturn(0xff, 0xfe, 0), None)),
        inc_chk(
            0x100,
            vec![make_small_operand(0xff), make_small_operand(0xfe)],
            &mut reader,
            0x00,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariableAndReturn(0xff, 0xfe, 1), None)),
        inc_chk(
            0x100,
            vec![make_small_operand(0xff), make_small_operand(0xfe)],
            &mut reader,
            0x01,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariableAndReturn(0xff, 0xfe, 1), None)),
        inc_chk(
            0x100,
            vec![make_small_operand(0xff), make_small_operand(0xfe)],
            &mut reader,
            0x01,
            false,
            DebugVerbosity::None
        )
    );

    reader.set_variable(0xff, 65535);

    assert_eq!(
        Ok((Action::StoreVariable(0xff, 0, 0x100, true), None)),
        inc_chk(
            0x100,
            vec![make_small_operand(0xff), make_large_operand(65535)],
            &mut reader,
            0x40,
            false,
            DebugVerbosity::None
        )
    );

    Ok(())
}

/// Helper function used to simplify branch instructions by
/// handling branch_on_true and the 0/1 return offsets
pub fn handle_branch(
    result: bool,
    branch_on_true: bool,
    pc_address: usize,
    branch_addr: usize,
) -> Action {
    let branch = if branch_on_true { result } else { !result };

    if !branch {
        Action::Jump(pc_address)
    } else {
        match branch_addr {
            0 => Action::Return(ZMACHINE_FALSE),
            1 => Action::Return(ZMACHINE_TRUE),
            _ => Action::Jump(branch_addr),
        }
    }
}

///
/// Jump if a = b, c, or d
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#je
///
pub fn je(
    pc_address: usize,
    operands: Vec<Operand>,
    branch_addr: usize,
    branch_on_true: bool,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let operand_count = operands.len();
    if operand_count < 2 {
        return Err(ZmachineError::InstructionsExpected2Operands());
    }

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_branch(
            "je",
            &operands,
            branch_addr,
            branch_on_true,
        )),
    };

    let mut result = operands[0].operand_value == operands[1].operand_value;
    if !result && operand_count > 2 {
        result = operands[0].operand_value == operands[2].operand_value;
    }
    if !result && operand_count > 3 {
        result = operands[0].operand_value == operands[3].operand_value;
    }

    Ok((
        handle_branch(result, branch_on_true, pc_address, branch_addr),
        instruction_text,
    ))
}

#[test]
fn test_je() -> Result<(), ZmachineError> {
    assert_eq!(
        Err(ZmachineError::InstructionsExpected2Operands()),
        je(0x100, vec![], 0x40, true, DebugVerbosity::None)
    );

    assert_eq!(
        Err(ZmachineError::InstructionsExpected2Operands()),
        je(
            0x100,
            vec![Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            }],
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        je(
            0x100,
            vec![
                Operand {
                    operand_value: 0x01,
                    operand_type: OperandType::Small,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x00,
                    operand_type: OperandType::Small,
                    variable_number: 0
                }
            ],
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x40), None)),
        je(
            0x100,
            vec![
                Operand {
                    operand_value: 0x01,
                    operand_type: OperandType::Small,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x00,
                    operand_type: OperandType::Small,
                    variable_number: 0
                }
            ],
            0x40,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Return(0), None)),
        je(
            0x100,
            vec![
                Operand {
                    operand_value: 0x01,
                    operand_type: OperandType::Small,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x00,
                    operand_type: OperandType::Small,
                    variable_number: 0
                }
            ],
            0x00,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Return(1), None)),
        je(
            0x100,
            vec![
                Operand {
                    operand_value: 0x01,
                    operand_type: OperandType::Small,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x00,
                    operand_type: OperandType::Small,
                    variable_number: 0
                }
            ],
            0x01,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x40), None)),
        je(
            0x100,
            vec![
                Operand {
                    operand_value: 0x01,
                    operand_type: OperandType::Small,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x01,
                    operand_type: OperandType::Small,
                    variable_number: 0
                }
            ],
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x40), None)),
        je(
            0x100,
            vec![
                Operand {
                    operand_value: 0x01,
                    operand_type: OperandType::Small,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x02,
                    operand_type: OperandType::Small,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x01,
                    operand_type: OperandType::Small,
                    variable_number: 0
                }
            ],
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x40), None)),
        je(
            0x100,
            vec![
                Operand {
                    operand_value: 0x01,
                    operand_type: OperandType::Small,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x02,
                    operand_type: OperandType::Small,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x03,
                    operand_type: OperandType::Small,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x01,
                    operand_type: OperandType::Small,
                    variable_number: 0
                }
            ],
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        je(
            0x100,
            vec![
                Operand {
                    operand_value: 0x22,
                    operand_type: OperandType::Small,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x02,
                    operand_type: OperandType::Small,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x03,
                    operand_type: OperandType::Small,
                    variable_number: 0
                },
                Operand {
                    operand_value: 0x01,
                    operand_type: OperandType::Small,
                    variable_number: 0
                }
            ],
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Jump if a > b (signed)
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#jg
///
pub fn jg(
    pc_address: usize,
    a: Operand,
    b: Operand,
    branch_addr: usize,
    branch_on_true: bool,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_branch(
            "jg",
            &[a, b],
            branch_addr,
            branch_on_true,
        )),
    };

    Ok((
        handle_branch(
            word_to_signed(a.operand_value) > word_to_signed(b.operand_value),
            branch_on_true,
            pc_address,
            branch_addr,
        ),
        instruction_text,
    ))
}

#[test]
fn test_jg() -> Result<(), ZmachineError> {
    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        jg(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x40), None)),
        jg(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Return(0), None)),
        jg(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x00,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Return(1), None)),
        jg(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x01,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        jg(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        jg(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x40), None)),
        jg(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x40), None)),
        jg(
            0x40,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Jump if a = 0
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#jz
///
pub fn jz(
    pc_address: usize,
    a: Operand,
    branch_addr: usize,
    branch_on_true: bool,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_branch(
            "jz",
            &[a],
            branch_addr,
            branch_on_true,
        )),
    };

    Ok((
        handle_branch(
            a.operand_value == 0,
            branch_on_true,
            pc_address,
            branch_addr,
        ),
        instruction_text,
    ))
}

#[test]
fn test_jz() -> Result<(), ZmachineError> {
    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        jz(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x40), None)),
        jz(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Return(0), None)),
        jz(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x00,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Return(1), None)),
        jz(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x01,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        jz(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        jz(
            0x100,
            Operand {
                operand_value: 0x02,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        jz(
            0x100,
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Jump if a < b (signed)
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#jl
///
pub fn jl(
    pc_address: usize,
    a: Operand,
    b: Operand,
    branch_addr: usize,
    branch_on_true: bool,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_branch(
            "jl",
            &[a, b],
            branch_addr,
            branch_on_true,
        )),
    };

    Ok((
        handle_branch(
            word_to_signed(a.operand_value) < word_to_signed(b.operand_value),
            branch_on_true,
            pc_address,
            branch_addr,
        ),
        instruction_text,
    ))
}

#[test]
fn test_jl() -> Result<(), ZmachineError> {
    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        jl(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x40), None)),
        jl(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Return(0), None)),
        jl(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x00,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Return(1), None)),
        jl(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x01,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x40), None)),
        jl(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        jl(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            true,
            DebugVerbosity::None
        ),
    );

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        jl(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x40), None)),
        jl(
            0x40,
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            true,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Signed addition of a and b
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#store
///
pub fn add(
    pc_address: usize,
    a: Operand,
    b: Operand,
    store_var: u8,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let s: i32 = word_to_signed(a.operand_value) as i32 + word_to_signed(b.operand_value) as i32;
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_store("add", &[a, b], store_var)),
    };

    Ok((
        Action::StoreVariable(
            store_var,
            signed_to_word((s % 0x10000) as i16),
            pc_address,
            false,
        ),
        instruction_text,
    ))
}

#[test]
fn test_add() -> Result<(), ZmachineError> {
    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        add(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 1, 0x100, false), None)),
        add(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        ),
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 1, 0x100, false), None)),
        add(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 65535, 0x100, false), None)),
        add(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 65534, 0x100, false), None)),
        add(
            0x100,
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        ),
    );

    // Test overflow. See 2.3.2 https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
    assert_eq!(
        Ok((Action::StoreVariable(0x40, 14464, 0x100, false), None)),
        add(
            0x100,
            Operand {
                operand_value: 40000,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 40000,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );
    Ok(())
}

///
/// Signed subtraction of a - b
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#sub
///
pub fn subtract(
    pc_address: usize,
    a: Operand,
    b: Operand,
    store_var: u8,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let s: i32 = word_to_signed(a.operand_value) as i32 - word_to_signed(b.operand_value) as i32;

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_store("sub", &[a, b], store_var)),
    };
    Ok((
        Action::StoreVariable(
            store_var,
            signed_to_word((s % 0x10000) as i16),
            pc_address,
            false,
        ),
        instruction_text,
    ))
}

#[test]
fn test_subtract() -> Result<(), ZmachineError> {
    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        subtract(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 1, 0x100, false), None)),
        subtract(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        ),
    );

    assert_eq!(
        Ok((
            Action::StoreVariable(0x40, signed_to_word(-1), 0x100, false),
            None
        )),
        subtract(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 1, 0x100, false), None)),
        subtract(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 65534, 0x100, false), None)),
        subtract(
            0x100,
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 1, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        subtract(
            0x100,
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    // Test overflow. See 2.3.2 https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
    assert_eq!(
        Ok((Action::StoreVariable(0x40, 58304, 0x100, false), None)),
        subtract(
            0x100,
            Operand {
                operand_value: MAX_SIGNED + 1,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 40000,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );
    Ok(())
}

///
/// Signed multiplication of a * b
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#mul
///
pub fn mul(
    pc_address: usize,
    a: Operand,
    b: Operand,
    store_var: u8,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let s: i32 = word_to_signed(a.operand_value) as i32 * word_to_signed(b.operand_value) as i32;
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_store("mul", &[a, b], store_var)),
    };

    Ok((
        Action::StoreVariable(
            store_var,
            signed_to_word((s % 0x10000) as i16),
            pc_address,
            false,
        ),
        instruction_text,
    ))
}

#[test]
fn test_mul() -> Result<(), ZmachineError> {
    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        mul(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        mul(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 1, 0x100, false), None)),
        mul(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 10, 0x100, false), None)),
        mul(
            0x100,
            Operand {
                operand_value: 0x02,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x05,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 65535, 0x100, false), None)),
        mul(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 65535, 0x100, false), None)),
        mul(
            0x100,
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 1,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 1, 0x100, false), None)),
        mul(
            0x100,
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    // Test overflow. See 2.3.2 https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
    assert_eq!(
        Ok((Action::StoreVariable(0x40, 65532, 0x100, false), None)),
        mul(
            0x100,
            Operand {
                operand_value: MAX_SIGNED,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 4,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );
    Ok(())
}

///
/// Signed divsion of a / b
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#div
///
pub fn div(
    pc_address: usize,
    a: Operand,
    b: Operand,
    store_var: u8,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_store("div", &[a, b], store_var)),
    };

    if b.operand_value == 0 {
        Err(ZmachineError::InstructionsDivideByZero())
    } else {
        let s: i32 =
            word_to_signed(a.operand_value) as i32 / word_to_signed(b.operand_value) as i32;
        Ok((
            Action::StoreVariable(
                store_var,
                signed_to_word((s % 0x10000) as i16),
                pc_address,
                false,
            ),
            instruction_text,
        ))
    }
}

#[test]
fn test_div() -> Result<(), ZmachineError> {
    assert_eq!(
        Err(ZmachineError::InstructionsDivideByZero()),
        div(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Err(ZmachineError::InstructionsDivideByZero()),
        div(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 1, 0x100, false), None)),
        div(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 2, 0x100, false), None)),
        div(
            0x100,
            Operand {
                operand_value: 0x05,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x02,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 65535, 0x100, false), None)),
        div(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 65535, 0x100, false), None)),
        div(
            0x100,
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 1, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 1, 0x100, false), None)),
        div(
            0x100,
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    // Test overflow. See 2.3.2 https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
    assert_eq!(
        Ok((Action::StoreVariable(0x40, 8191, 0x100, false), None)),
        div(
            0x100,
            Operand {
                operand_value: MAX_SIGNED,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 4,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Remainder of signed division of a / b
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#mod
///
pub fn zmod(
    pc_address: usize,
    a: Operand,
    b: Operand,
    store_var: u8,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_store("mod", &[a, b], store_var)),
    };

    if b.operand_value == 0 {
        Err(ZmachineError::InstructionsDivideByZero())
    } else {
        let s: i32 =
            word_to_signed(a.operand_value) as i32 % word_to_signed(b.operand_value) as i32;
        Ok((
            Action::StoreVariable(
                store_var,
                signed_to_word((s % 0x10000) as i16),
                pc_address,
                false,
            ),
            instruction_text,
        ))
    }
}

#[test]
fn test_zmod() -> Result<(), ZmachineError> {
    assert_eq!(
        Err(ZmachineError::InstructionsDivideByZero()),
        zmod(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Err(ZmachineError::InstructionsDivideByZero()),
        zmod(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        zmod(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 1, 0x100, false), None)),
        zmod(
            0x100,
            Operand {
                operand_value: 0x05,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x02,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        ),
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        zmod(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        zmod(
            0x100,
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 1,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        zmod(
            0x100,
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 65535, // -1, https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    // Test overflow. See 2.3.2 https://www.inform-fiction.org/zmachine/standards/z1point1/sect02.html
    assert_eq!(
        Ok((Action::StoreVariable(0x40, 3, 0x100, false), None)),
        zmod(
            0x100,
            Operand {
                operand_value: MAX_SIGNED,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 4,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );
    Ok(())
}

///
/// Bitwise negation of a, stored in store_var
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#not
///
pub fn znot(
    pc_address: usize,
    a: Operand,
    store_var: u8,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_store("not", &[a], store_var)),
    };

    Ok((
        Action::StoreVariable(store_var, !a.operand_value, pc_address, false),
        instruction_text,
    ))
}

#[test]
fn test_znot() -> Result<(), ZmachineError> {
    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        znot(
            0x100,
            make_large_operand(0xffff),
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0xffff, 0x100, false), None)),
        znot(0x100, make_small_operand(0x00), 0x40, DebugVerbosity::None)
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0xfffe, 0x100, false), None)),
        znot(0x100, make_large_operand(0x01), 0x40, DebugVerbosity::None)
    );

    Ok(())
}

///
/// Remainder of bitwise and of a & b
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#and
///
pub fn zand(
    pc_address: usize,
    a: Operand,
    b: Operand,
    store_var: u8,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_store("and", &[a, b], store_var)),
    };

    Ok((
        Action::StoreVariable(
            store_var,
            a.operand_value & b.operand_value,
            pc_address,
            false,
        ),
        instruction_text,
    ))
}

#[test]
fn test_zand() -> Result<(), ZmachineError> {
    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        zand(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        zand(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        zand(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 1, 0x100, false), None)),
        zand(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0x1234, 0x100, false), None)),
        zand(
            0x100,
            Operand {
                operand_value: 0xffff,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x1234,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Remainder of or and of a | b
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#or
///
pub fn zor(
    pc_address: usize,
    a: Operand,
    b: Operand,
    store_var: u8,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_store("or", &[a, b], store_var)),
    };

    Ok((
        Action::StoreVariable(
            store_var,
            a.operand_value | b.operand_value,
            pc_address,
            false,
        ),
        instruction_text,
    ))
}

#[test]
fn test_zor() -> Result<(), ZmachineError> {
    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        zor(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 1, 0x100, false), None)),
        zor(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 1, 0x100, false), None)),
        zor(
            0x100,
            Operand {
                operand_value: 0x00,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 1, 0x100, false), None)),
        zor(
            0x100,
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x01,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0xffff, 0x100, false), None)),
        zor(
            0x100,
            Operand {
                operand_value: 0xffff,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            Operand {
                operand_value: 0x1234,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Increment a variable
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#inc
///
pub fn inc<T: MemoryReader>(
    pc_address: usize,
    var_op: Operand,
    reader: &mut T,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let variable_number = var_op.operand_value;
    if variable_number > 255 {
        return Err(ZmachineError::InstructionsOperandVariableOutOfBounds(
            variable_number,
        ));
    }

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("inc", &[var_op])),
    };

    let s: i32 = word_to_signed(reader.get_variable(variable_number as u8)?) as i32;
    Ok((
        Action::StoreVariable(
            variable_number as u8,
            signed_to_word(((s + 1) % 0x10000) as i16),
            pc_address,
            false,
        ),
        instruction_text,
    ))
}

#[test]
fn test_inc() -> Result<(), ZmachineError> {
    // No arguments, return variable 0xff
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x0f, 0x00, 0x05, 0x11, 0x11, 0x01, 0x01,
    ]);

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 1, 0x100, false), None)),
        inc(
            0x100,
            Operand {
                operand_value: 0x40,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            &mut reader,
            DebugVerbosity::None
        )
    );

    reader.set_variable(0x40, signed_to_word(-1));
    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        inc(
            0x100,
            Operand {
                operand_value: 0x40,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            &mut reader,
            DebugVerbosity::None
        )
    );

    reader.set_variable(0x40, MAX_SIGNED);
    assert_eq!(
        Ok((Action::StoreVariable(0x40, 32768, 0x100, false), None)),
        inc(
            0x100,
            Operand {
                operand_value: 0x40,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            &mut reader,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Decrement a variable
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#dec
///
pub fn dec<T: MemoryReader>(
    pc_address: usize,
    var_op: Operand,
    reader: &mut T,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let variable_number = var_op.operand_value;
    if variable_number > 255 {
        return Err(ZmachineError::InstructionsOperandVariableOutOfBounds(
            variable_number,
        ));
    }

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("dec", &[var_op])),
    };

    let s: i32 = word_to_signed(reader.get_variable(variable_number as u8)?) as i32;
    Ok((
        Action::StoreVariable(
            variable_number as u8,
            signed_to_word(((s - 1) % 0x10000) as i16),
            pc_address,
            false,
        ),
        instruction_text,
    ))
}

#[test]
fn test_dec() -> Result<(), ZmachineError> {
    // No arguments, return variable 0xff
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x0f, 0x00, 0x05, 0x11, 0x11, 0x01, 0x01,
    ]);

    assert_eq!(
        Ok((
            Action::StoreVariable(0x40, signed_to_word(-1), 0x100, false),
            None
        )),
        dec(
            0x100,
            Operand {
                operand_value: 0x40,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            &mut reader,
            DebugVerbosity::None
        )
    );

    reader.set_variable(0x40, 1);
    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        dec(
            0x100,
            Operand {
                operand_value: 0x40,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            &mut reader,
            DebugVerbosity::None
        )
    );

    reader.set_variable(0x40, MAX_UNSIGNED as u16);
    assert_eq!(
        Ok((Action::StoreVariable(0x40, 65535, 0x100, false), None)),
        dec(
            0x100,
            Operand {
                operand_value: 0x40,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            &mut reader,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Store an object's parent
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#get_parent
///
pub fn get_parent<T: ObjectTreeReader>(
    pc_address: usize,
    obj: Operand,
    store_var: u8,
    reader: &mut T,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_store("get_parent", &[obj], store_var)),
    };

    let parent_obj = reader.get_parent(obj.operand_value as usize)?;

    if parent_obj == obj.operand_value as usize && parent_obj != 0 {
        return Err(ZmachineError::ObjectSelfReference(parent_obj));
    }
    Ok((
        Action::StoreVariable(store_var, parent_obj as u16, pc_address, false),
        instruction_text,
    ))
}

#[test]
fn test_get_parent() -> Result<(), ZmachineError> {
    // No arguments, return variable 0xff
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x0f, 0x00, 0x05, 0x11, 0x11, 0x01, 0x01,
    ]);

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        get_parent(
            0x100,
            Operand {
                operand_value: 0,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            &mut reader,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        get_parent(
            0x100,
            Operand {
                operand_value: 1,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            &mut reader,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 1, 0x100, false), None)),
        get_parent(
            0x100,
            Operand {
                operand_value: 2,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            &mut reader,
            DebugVerbosity::None
        )
    );

    Ok(())
}

pub fn branch_and_store(
    pc_address: usize,
    instruction_text: Option<String>,
    branch_on_true: bool,
    object_number: u16,
    variable_number: u8,
    branch_addr: usize,
) -> Result<(Action, Option<String>), ZmachineError> {
    // Have to duplicate the branch logic in handle_branch since the
    // StoreVariableReturn might need to be used
    let branch = if branch_on_true {
        object_number != 0
    } else {
        object_number == 0
    };

    let action = if !branch {
        Action::StoreVariable(variable_number, object_number, pc_address, true)
    } else {
        match branch_addr {
            0 => Action::StoreVariableAndReturn(variable_number, object_number, ZMACHINE_FALSE),
            1 => Action::StoreVariableAndReturn(variable_number, object_number, ZMACHINE_TRUE),
            _ => Action::StoreVariable(variable_number, object_number, branch_addr, true),
        }
    };

    Ok((action, instruction_text))
}

#[test]
pub fn test_branch_and_store() -> Result<(), ZmachineError> {
    // Test store path
    assert_eq!(
        Ok((Action::StoreVariable(2, 0, 0x4321, true), None)),
        branch_and_store(0x4321, None, true, 0, 2, 0x1234)
    );

    // Test store, return false
    assert_eq!(
        Ok((Action::StoreVariableAndReturn(2, 1, ZMACHINE_FALSE), None)),
        branch_and_store(0x4321, None, true, 1, 2, 0)
    );

    // Test store, return true
    assert_eq!(
        Ok((Action::StoreVariableAndReturn(2, 1, ZMACHINE_TRUE), None)),
        branch_and_store(0x4321, None, true, 1, 2, 1)
    );

    // Test store, don't return
    assert_eq!(
        Ok((Action::StoreVariable(2, 0, 0x4321, true), None)),
        branch_and_store(0x4321, None, true, 0, 2, 2)
    );
    //
    // With branch on true flipped, behavior inverts
    //
    assert_eq!(
        Ok((Action::StoreVariable(2, 1, 0x4321, true), None)),
        branch_and_store(0x4321, None, false, 1, 2, 0x1234)
    );

    assert_eq!(
        Ok((Action::StoreVariableAndReturn(2, 0, ZMACHINE_FALSE), None)),
        branch_and_store(0x4321, None, false, 0, 2, 0)
    );

    assert_eq!(
        Ok((Action::StoreVariableAndReturn(2, 0, ZMACHINE_TRUE), None)),
        branch_and_store(0x4321, None, false, 0, 2, 1)
    );

    assert_eq!(
        Ok((Action::StoreVariable(2, 1, 0x4321, true), None)),
        branch_and_store(0x4321, None, false, 1, 2, 2)
    );
    Ok(())
}

///
/// Store an object's first child
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#get_child
///
pub fn get_child<T: ObjectTreeReader>(
    pc_address: usize,
    obj: Operand,
    store_var: u8,
    reader: &mut T,
    branch_addr: usize,
    branch_on_true: bool,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_branch_and_store(
            "get_child",
            &[obj],
            branch_addr,
            branch_on_true,
            store_var,
        )),
    };

    let child_obj = reader.get_child(obj.operand_value as usize)?;
    if child_obj == obj.operand_value as usize && child_obj != 0 {
        return Err(ZmachineError::ObjectSelfReference(child_obj));
    }

    branch_and_store(
        pc_address,
        instruction_text,
        branch_on_true,
        child_obj as u16,
        store_var,
        branch_addr,
    )
}

#[test]
fn test_get_child() -> Result<(), ZmachineError> {
    // No arguments, return variable 0xff
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x0f, 0x00, 0x05, 0x11, 0x11, 0x01, 0x01,
    ]);

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, true), None)),
        get_child(
            0x100,
            Operand {
                operand_value: 0,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            &mut reader,
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 2, 0xffff, true), None)),
        get_child(
            0x100,
            Operand {
                operand_value: 1,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            &mut reader,
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, true), None)),
        get_child(
            0x100,
            Operand {
                operand_value: 2,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            &mut reader,
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0xffff, true), None)),
        get_child(
            0x100,
            Operand {
                operand_value: 2,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            &mut reader,
            0xffff,
            false,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Store an object's sibling, branching if it is non-zero
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#get_child
///
pub fn get_sibling<T: ObjectTreeReader>(
    pc_address: usize,
    obj: Operand,
    store_var: u8,
    reader: &mut T,
    branch_addr: usize,
    branch_on_true: bool,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_branch(
            "get_sibling",
            &[obj],
            branch_addr,
            branch_on_true,
        )),
    };

    let sibling_obj = reader.get_sibling(obj.operand_value as usize)?;

    if sibling_obj == obj.operand_value as usize && sibling_obj != 0 {
        return Err(ZmachineError::ObjectSelfReference(sibling_obj));
    }

    branch_and_store(
        pc_address,
        instruction_text,
        branch_on_true,
        sibling_obj as u16,
        store_var,
        branch_addr,
    )
}

#[test]
fn test_get_sibling() -> Result<(), ZmachineError> {
    // No arguments, return variable 0xff
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x0f, 0x00, 0x05, 0x11, 0x11, 0x01, 0x01,
    ]);

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, true), None)),
        get_sibling(
            0x100,
            Operand {
                operand_value: 0,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            &mut reader,
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 3, 0xffff, true), None)),
        get_sibling(
            0x100,
            Operand {
                operand_value: 2,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            &mut reader,
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, true), None)),
        get_sibling(
            0x100,
            Operand {
                operand_value: 1,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            &mut reader,
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0xffff, true), None)),
        get_sibling(
            0x100,
            Operand {
                operand_value: 1,
                operand_type: OperandType::Small,
                variable_number: 0
            },
            0x40,
            &mut reader,
            0xffff,
            false,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Insert object a in b
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#insert_obj
///
pub fn insert_obj(
    pc_address: usize,
    a: Operand,
    b: Operand,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("insert_obj", &[a, b])),
    };

    Ok((
        Action::InsertObject(a.operand_value, b.operand_value, pc_address),
        instruction_text,
    ))
}
#[test]
fn test_insert_obj() -> Result<(), ZmachineError> {
    assert_eq!(
        Ok((Action::InsertObject(0x01, 0x02, 0x100), None)),
        insert_obj(
            0x100,
            make_small_operand(1),
            make_small_operand(2),
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Remove object a from its parent
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#remove_obj
///
pub fn remove_obj(
    pc_address: usize,
    a: Operand,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("remove_obj", &[a])),
    };

    Ok((
        Action::RemoveObject(a.operand_value, pc_address),
        instruction_text,
    ))
}
#[test]
fn test_remove_obj() -> Result<(), ZmachineError> {
    assert_eq!(
        Ok((Action::RemoveObject(0x01, 0x100), None)),
        remove_obj(0x100, make_small_operand(1), DebugVerbosity::None)
    );

    Ok(())
}

///
/// Print the short name for an object
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#print_obj
///
pub fn print_obj<T: ObjectTreeReader>(
    pc_address: usize,
    a: Operand,
    reader: &mut T,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("print_obj", &[a])),
    };

    Ok((
        Action::PrintString(reader.get_short_name(a.operand_value as usize)?, pc_address),
        instruction_text,
    ))
}

#[test]
fn test_print_obj() -> Result<(), ZmachineError> {
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x0f, 0x00, 0x05, 0x11, 0x11, 0x01, 0x01,
    ]);

    assert_eq!(
        Ok((Action::PrintString(String::from("Object 1"), 0x100), None)),
        print_obj(
            0x100,
            make_small_operand(1),
            &mut reader,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Branch if a is a child of b
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#get_child
///
pub fn jin<T: ObjectTreeReader>(
    pc_address: usize,
    a: Operand,
    b: Operand,
    reader: &mut T,
    branch_addr: usize,
    branch_on_true: bool,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_branch(
            "jin",
            &[a, b],
            branch_addr,
            branch_on_true,
        )),
    };

    let parent_obj = reader.get_parent(a.operand_value as usize)? as u16;

    if parent_obj == a.operand_value && parent_obj != 0 {
        return Err(ZmachineError::ObjectSelfReference(parent_obj as usize));
    }

    Ok((
        handle_branch(
            parent_obj == b.operand_value && parent_obj != 0,
            branch_on_true,
            pc_address,
            branch_addr,
        ),
        instruction_text,
    ))
}

#[test]
fn test_jin() -> Result<(), ZmachineError> {
    // No arguments, return variable 0xff
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x0f, 0x00, 0x05, 0x11, 0x11, 0x01, 0x01,
    ]);

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        jin(
            0x100,
            make_small_operand(1),
            make_small_operand(0),
            &mut reader,
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        jin(
            0x100,
            make_small_operand(1),
            make_small_operand(2),
            &mut reader,
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0xffff), None)),
        jin(
            0x100,
            make_small_operand(2),
            make_small_operand(1),
            &mut reader,
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0xffff), None)),
        jin(
            0x100,
            make_small_operand(3),
            make_small_operand(1),
            &mut reader,
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        jin(
            0x100,
            make_small_operand(3),
            make_small_operand(1),
            &mut reader,
            0xffff,
            false,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Branch if all flags set
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#get_child
///
pub fn ztest(
    pc_address: usize,
    bitmap: Operand,
    flags: Operand,
    branch_addr: usize,
    branch_on_true: bool,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_branch(
            "test",
            &[bitmap, flags],
            branch_addr,
            branch_on_true,
        )),
    };

    Ok((
        handle_branch(
            (bitmap.operand_value & flags.operand_value) == flags.operand_value,
            branch_on_true,
            pc_address,
            branch_addr,
        ),
        instruction_text,
    ))
}

#[test]
fn test_ztest() -> Result<(), ZmachineError> {
    // No arguments, return variable 0xff

    assert_eq!(
        Ok((Action::Jump(0xffff), None)),
        ztest(
            0x100,
            make_small_operand(0),
            make_small_operand(0),
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        ztest(
            0x100,
            make_small_operand(0),
            make_small_operand(0),
            0xffff,
            false,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        ztest(
            0x100,
            make_small_operand(0),
            make_small_operand(1),
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0xffff), None)),
        ztest(
            0x100,
            make_small_operand(1),
            make_small_operand(1),
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0xffff), None)),
        ztest(
            0x100,
            make_small_operand(3),
            make_small_operand(1),
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        ztest(
            0x100,
            make_small_operand(1),
            make_small_operand(3),
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0xffff), None)),
        ztest(
            0x100,
            make_large_operand(0xffff),
            make_large_operand(0x00ff),
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        ztest(
            0x100,
            make_large_operand(0x00ff),
            make_large_operand(0xffff),
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Branch if a has attribute b
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#get_child
///
pub fn test_attr<T: ObjectTreeReader>(
    pc_address: usize,
    a: Operand,
    b: Operand,
    reader: &mut T,
    branch_addr: usize,
    branch_on_true: bool,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    if b.operand_value > 32 {
        return Err(ZmachineError::OutOfBoundsAttribute(b.operand_value as u8));
    }

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_branch(
            "test_attr",
            &[a, b],
            branch_addr,
            branch_on_true,
        )),
    };

    let attr = reader.get_attribute(a.operand_value as usize, b.operand_value as u8)?;
    Ok((
        handle_branch(attr, branch_on_true, pc_address, branch_addr),
        instruction_text,
    ))
}

#[test]
fn test_test_attr() -> Result<(), ZmachineError> {
    // No arguments, return variable 0xff
    let mut reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x0f, 0x00, 0x05, 0x11, 0x11, 0x01, 0x01,
    ]);

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        test_attr(
            0x100,
            make_small_operand(1),
            make_small_operand(0),
            &mut reader,
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        test_attr(
            0x100,
            make_small_operand(1),
            make_small_operand(2),
            &mut reader,
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0xffff), None)),
        test_attr(
            0x100,
            make_small_operand(2),
            make_small_operand(3),
            &mut reader,
            0xffff,
            true,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        test_attr(
            0x100,
            make_small_operand(2),
            make_small_operand(3),
            &mut reader,
            0xffff,
            false,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Set attribute b on object a
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#set_attr
///
pub fn set_attr(
    pc_address: usize,
    a: Operand,
    b: Operand,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    if b.operand_value > 32 {
        return Err(ZmachineError::OutOfBoundsAttribute(b.operand_value as u8));
    }

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("set_attr", &[a, b])),
    };

    Ok((
        Action::SetAttr(a.operand_value, b.operand_value as u8, true, pc_address),
        instruction_text,
    ))
}

#[test]
fn test_set_attr() -> Result<(), ZmachineError> {
    // No arguments, return variable 0xff
    assert_eq!(
        Ok((Action::SetAttr(1, 0, true, 0x100), None)),
        set_attr(
            0x100,
            make_small_operand(1),
            make_small_operand(0),
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Clear attribute b on object a
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#clear_attr
///
pub fn clear_attr(
    pc_address: usize,
    a: Operand,
    b: Operand,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    if b.operand_value > 32 {
        return Err(ZmachineError::OutOfBoundsAttribute(b.operand_value as u8));
    }

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("clear_attr", &[a, b])),
    };

    Ok((
        Action::SetAttr(a.operand_value, b.operand_value as u8, false, pc_address),
        instruction_text,
    ))
}

#[test]
fn test_clear_attr() -> Result<(), ZmachineError> {
    // No arguments, return variable 0xff

    assert_eq!(
        Ok((Action::SetAttr(1, 0, false, 0x100), None)),
        clear_attr(
            0x100,
            make_small_operand(1),
            make_small_operand(0),
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Set attribute b on object a
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#get_next_prop
///
pub fn get_next_prop<T: ObjectTreeReader>(
    pc_address: usize,
    a: Operand,
    b: Operand,
    store_var: u8,
    reader: &T,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("get_next_prop", &[a, b])),
    };

    let next_prop = reader.get_next_property(a.operand_value as usize, b.operand_value as usize)?;
    Ok((
        Action::StoreVariable(store_var, next_prop as u16, pc_address, false),
        instruction_text,
    ))
}

#[test]
fn test_get_next_prop() -> Result<(), ZmachineError> {
    let reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x0f, 0x00, 0x05, 0x11, 0x11, 0x01, 0x01,
    ]);

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 2, 0x100, false), None)),
        get_next_prop(
            0x100,
            make_small_operand(2),
            make_small_operand(0),
            0x40,
            &reader,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 3, 0x100, false), None)),
        get_next_prop(
            0x100,
            make_small_operand(2),
            make_small_operand(2),
            0x40,
            &reader,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        get_next_prop(
            0x100,
            make_small_operand(2),
            make_small_operand(3),
            0x40,
            &reader,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Get the property value for an object. This will return an error if the property length > 2.
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#get_prop
///
pub fn get_prop<T: ObjectTreeReader>(
    pc_address: usize,
    a: Operand,
    b: Operand,
    store_var: u8,
    reader: &T,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("get_prop", &[a, b])),
    };

    let property = reader.get_property(a.operand_value as usize, b.operand_value as usize)?;
    if property.size > 2 {
        Err(ZmachineError::ObjectInvalidPropertySize(property.size))
    } else {
        Ok((
            Action::StoreVariable(store_var, property.value as u16, pc_address, false),
            instruction_text,
        ))
    }
}

#[test]
fn test_get_prop() -> Result<(), ZmachineError> {
    let reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x0f, 0x00, 0x05, 0x11, 0x11, 0x01, 0x01,
    ]);

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0xff, 0x100, false), None)),
        get_prop(
            0x100,
            make_small_operand(1),
            make_small_operand(2),
            0x40,
            &reader,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0xffff, 0x100, false), None)),
        get_prop(
            0x100,
            make_small_operand(1),
            make_small_operand(3),
            0x40,
            &reader,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Err(ZmachineError::ObjectInvalidPropertySize(3)),
        get_prop(
            0x100,
            make_small_operand(1),
            make_small_operand(4),
            0x40,
            &reader,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Err(ZmachineError::ObjectInvalidProperty(4)),
        get_prop(
            0x100,
            make_small_operand(2),
            make_small_operand(4),
            0x40,
            &reader,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Set the property value for an object. This will return an error if the property length > 2.
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#get_prop
///
pub fn put_prop<T: ObjectTreeReader>(
    pc_address: usize,
    a: Operand,
    b: Operand,
    c: Operand,
    reader: &T,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("put_prop", &[a, b, c])),
    };

    let property = reader.get_property(a.operand_value as usize, b.operand_value as usize)?;
    if property.size > 2 {
        Err(ZmachineError::ObjectInvalidPropertySize(property.size))
    } else {
        Ok((
            Action::SetProperty(
                a.operand_value,
                b.operand_value,
                c.operand_value,
                pc_address,
            ),
            instruction_text,
        ))
    }
}

#[test]
fn test_put_prop() -> Result<(), ZmachineError> {
    let reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x0f, 0x00, 0x05, 0x11, 0x11, 0x01, 0x01,
    ]);

    assert_eq!(
        Ok((Action::SetProperty(1, 2, 3, 0x100), None)),
        put_prop(
            0x100,
            make_small_operand(1),
            make_small_operand(2),
            make_small_operand(3),
            &reader,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::SetProperty(1, 3, 0xffff, 0x100), None)),
        put_prop(
            0x100,
            make_small_operand(1),
            make_small_operand(3),
            make_large_operand(0xffff),
            &reader,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Err(ZmachineError::ObjectInvalidPropertySize(3)),
        put_prop(
            0x100,
            make_small_operand(1),
            make_small_operand(4),
            make_large_operand(0xffff),
            &reader,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Err(ZmachineError::ObjectInvalidProperty(4)),
        put_prop(
            0x100,
            make_small_operand(2),
            make_small_operand(4),
            make_large_operand(0xffff),
            &reader,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Get the address of property b on object a. Return 0 if no property exists.
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#get_prop_addr
///
pub fn get_prop_addr<T: ObjectTreeReader>(
    pc_address: usize,
    a: Operand,
    b: Operand,
    store_var: u8,
    reader: &T,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_store(
            "get_prop_addr",
            &[a, b],
            store_var,
        )),
    };

    // Function will return the start of the property, including the length byte
    // This should return the address 1 byte after
    let prop_addr =
        reader.get_property_address(a.operand_value as usize, b.operand_value as usize)?;

    Ok((
        Action::StoreVariable(store_var, prop_addr as u16, pc_address, false),
        instruction_text,
    ))
}

#[test]
fn test_get_prop_addr() -> Result<(), ZmachineError> {
    let reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x0f, 0x00, 0x05, 0x11, 0x11, 0x01, 0x01,
    ]);

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        get_prop_addr(
            0x100,
            make_small_operand(2),
            make_small_operand(0),
            0x40,
            &reader,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0x1234, 0x100, false), None)),
        get_prop_addr(
            0x100,
            make_small_operand(2),
            make_small_operand(3),
            0x40,
            &reader,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        get_prop_addr(
            0x100,
            make_small_operand(2),
            make_small_operand(2),
            0x40,
            &reader,
            DebugVerbosity::None
        )
    );

    Ok(())
}

///
/// Get the the length of the property at the address provided, .
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#get_prop_len
///
pub fn get_prop_len<T: ObjectTreeReader>(
    pc_address: usize,
    a: Operand,
    store_var: u8,
    reader: &T,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_store("get_prop_len", &[a], store_var)),
    };

    let prop_len = reader.get_property_length(a.operand_value as usize)?;
    Ok((
        Action::StoreVariable(store_var, prop_len as u16, pc_address, false),
        instruction_text,
    ))
}

#[test]
fn test_get_prop_len() -> Result<(), ZmachineError> {
    let reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x0f, 0x00, 0x05, 0x11, 0x11, 0x01, 0x01,
    ]);

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0, 0x100, false), None)),
        get_prop_len(
            0x100,
            make_large_operand(0x1230),
            0x40,
            &reader,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::StoreVariable(0x40, 0x4321, 0x100, false), None)),
        get_prop_len(
            0x100,
            make_large_operand(0x1234),
            0x40,
            &reader,
            DebugVerbosity::None
        )
    );
    Ok(())
}

///
/// Return a random number
///
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#random
///
pub fn zrandom(
    pc_address: usize,
    range: Operand,
    store_var: u8,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_store("random", &[range], store_var)),
    };

    if range.operand_value < MAX_SIGNED && range.operand_value > 0 {
        Ok((
            Action::RandomAndStore(range.operand_value, store_var, pc_address),
            instruction_text,
        ))
    } else {
        Ok((
            Action::ReseedRNGAndStore(range.operand_value, store_var, pc_address),
            instruction_text,
        ))
    }
}

#[test]
fn test_zrandom() -> Result<(), ZmachineError> {
    assert_eq!(
        Ok((Action::ReseedRNGAndStore(0, 0xff, 0x100), None)),
        zrandom(0x100, make_large_operand(0), 0xff, DebugVerbosity::None)
    );

    assert_eq!(
        Ok((Action::ReseedRNGAndStore(0xffff, 0xff, 0x100), None)),
        zrandom(
            0x100,
            make_large_operand(0xffff),
            0xff,
            DebugVerbosity::None
        )
    );

    assert_eq!(
        Ok((Action::RandomAndStore(0xcc, 0xff, 0x100), None)),
        zrandom(0x100, make_small_operand(0xcc), 0xff, DebugVerbosity::None)
    );

    Ok(())
}

fn verify<T: MemoryReader>(
    pc_address: usize,
    _reader: &T,
    branch_addr: usize,
    branch_on_true: bool,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_branch(
            "verify",
            &[],
            branch_addr,
            branch_on_true,
        )),
    };

    Ok((
        handle_branch(true, branch_on_true, pc_address, branch_addr),
        instruction_text,
    ))
}

#[test]
fn test_verify() -> Result<(), ZmachineError> {
    let reader = StubV123MemoryObjectReader::create_with_memory(vec![
        0x0f, 0x00, 0x05, 0x11, 0x11, 0x01, 0x01,
    ]);

    assert_eq!(
        Ok((Action::Jump(0xffff), None)),
        verify(0x100, &reader, 0xffff, true, DebugVerbosity::None)
    );

    assert_eq!(
        Ok((Action::Jump(0x100), None)),
        verify(0x100, &reader, 0xffff, false, DebugVerbosity::None)
    );

    Ok(())
}

///
/// Play a sound effect
///
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#sound_effect>
///  
///
pub fn sound_effect(
    pc_addr: usize,
    operands: Vec<Operand>,
    verbosity: DebugVerbosity,
    _version: ZCodeVersion,
) -> Result<(Action, Option<String>), ZmachineError> {
    // Will require 1 operand if first operand is 1/2, more if 3
    if operands.is_empty() {
        return Err(ZmachineError::InstructionsExpected1Operand());
    }
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("play_sound", &operands)),
    };

    // Sound effect 1/2 expect no additional operands, other sound effects
    // expect more
    let effect_number = operands[0].operand_value;
    if effect_number == 1 || effect_number == 2 {
        if operands.len() > 1 {
            Err(ZmachineError::InstructionsExpected1Operand())
        } else {
            Ok((
                Action::SoundEffect(operands[0].operand_value, 0, 0, pc_addr),
                instruction_text,
            ))
        }
    } else if operands.len() != 3 {
        Err(ZmachineError::InstructionsExpected3Operands())
    } else {
        Ok((
            Action::SoundEffect(
                operands[0].operand_value,
                operands[1].operand_value,
                operands[2].operand_value,
                pc_addr,
            ),
            instruction_text,
        ))
    }
}

#[test]
fn test_sound_effect() -> Result<(), ZmachineError> {
    assert_eq!(
        (Action::SoundEffect(0x11, 0x22, 0x33, 0x100), None),
        sound_effect(
            0x100,
            vec![
                make_small_operand(0x11),
                make_small_operand(0x22),
                make_small_operand(0x33),
            ],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )?
    );

    assert_eq!(
        Err(ZmachineError::InstructionsExpected3Operands()),
        sound_effect(
            0x100,
            vec![make_small_operand(0x11), make_small_operand(0x22),],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    assert_eq!(
        Err(ZmachineError::InstructionsExpected3Operands()),
        sound_effect(
            0x100,
            vec![make_small_operand(0x11),],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    assert_eq!(
        (Action::SoundEffect(0x1, 0, 0, 0x100), None),
        sound_effect(
            0x100,
            vec![make_small_operand(0x1),],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )?
    );

    assert_eq!(
        Err(ZmachineError::InstructionsExpected1Operand()),
        sound_effect(
            0x100,
            vec![make_small_operand(0x1), make_small_operand(0x22),],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    assert_eq!(
        Err(ZmachineError::InstructionsExpected1Operand()),
        sound_effect(
            0x100,
            vec![
                make_small_operand(0x1),
                make_small_operand(0x22),
                make_small_operand(0x33),
            ],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    assert_eq!(
        (Action::SoundEffect(0x2, 0, 0, 0x100), None),
        sound_effect(
            0x100,
            vec![make_small_operand(0x2),],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )?
    );

    assert_eq!(
        Err(ZmachineError::InstructionsExpected1Operand()),
        sound_effect(
            0x100,
            vec![make_small_operand(0x2), make_small_operand(0x22),],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    assert_eq!(
        Err(ZmachineError::InstructionsExpected1Operand()),
        sound_effect(
            0x100,
            vec![
                make_small_operand(0x2),
                make_small_operand(0x22),
                make_small_operand(0x33),
            ],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    Ok(())
}

///
/// Initiate a save
/// https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#save
///
pub fn save(
    pc_address: usize,
    branch_addr: usize,
    branch_on_true: bool,
    verbosity: DebugVerbosity,
    _version: ZCodeVersion,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_branch(
            "save",
            &[],
            branch_addr,
            branch_on_true,
        )),
    };

    Ok((
        Action::Save(branch_addr, branch_on_true, pc_address),
        instruction_text,
    ))
}

#[test]
fn test_save() -> Result<(), ZmachineError> {
    assert_eq!(
        (Action::Save(0x200, false, 0x100), None),
        save(0x100, 0x200, false, DebugVerbosity::None, ZCodeVersion::V3)?
    );
    Ok(())
}

///
/// Initiate a restore
///
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#restore>
///  
///
pub fn restore(
    pc_address: usize,
    branch_addr: usize,
    branch_on_true: bool,
    verbosity: DebugVerbosity,
    _version: ZCodeVersion,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text_branch(
            "restore",
            &[],
            branch_addr,
            branch_on_true,
        )),
    };

    Ok((
        Action::Restore(branch_addr, branch_on_true, pc_address),
        instruction_text,
    ))
}

#[test]
fn test_restore() -> Result<(), ZmachineError> {
    assert_eq!(
        (Action::Restore(20, false, 10), None),
        restore(10, 20, false, DebugVerbosity::None, ZCodeVersion::V3)?
    );

    Ok(())
}

///
/// Initiate a restart
///
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#restart>
///  
///
pub fn restart(
    verbosity: DebugVerbosity,
    _version: ZCodeVersion,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(String::from("restart")),
    };

    Ok((Action::Restart(), instruction_text))
}

#[test]
fn test_restart() -> Result<(), ZmachineError> {
    assert_eq!(
        (Action::Restart(), None),
        restart(DebugVerbosity::None, ZCodeVersion::V3)?
    );

    Ok(())
}

///
/// Split (or un-split) the window
///
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#split_window>
///
pub fn split_window(
    pc_addr: usize,
    lines: Operand,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("split_window", &[lines])),
    };

    Ok((
        Action::SplitWindow(lines.operand_value, pc_addr),
        instruction_text,
    ))
}

#[test]
fn test_split_window() -> Result<(), ZmachineError> {
    assert_eq!(
        (Action::SplitWindow(5, 0x100), None),
        split_window(0x100, make_small_operand(5), DebugVerbosity::None)?
    );

    Ok(())
}

///
/// Set the window
///
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#set_window>
///
pub fn set_window(
    pc_addr: usize,
    window: Operand,
    verbosity: DebugVerbosity,
) -> Result<(Action, Option<String>), ZmachineError> {
    let window_layout = match window.operand_value {
        0 => Ok(WindowLayout::Lower),
        1 => Ok(WindowLayout::Upper),
        _ => Err(ZmachineError::InstructionsInvalidSetWindowValue()),
    };

    match window_layout {
        Err(msg) => Err(msg),
        Ok(window_layout) => {
            let instruction_text = match verbosity {
                DebugVerbosity::None => None,
                _ => Some(make_instruction_text("set_window", &[window])),
            };

            Ok((Action::SetWindow(window_layout, pc_addr), instruction_text))
        }
    }
}

#[test]
fn test_set_window() -> Result<(), ZmachineError> {
    assert_eq!(
        Err(ZmachineError::InstructionsInvalidSetWindowValue()),
        set_window(0x100, make_small_operand(2), DebugVerbosity::None)
    );

    assert_eq!(
        (Action::SetWindow(WindowLayout::Upper, 0x100), None),
        set_window(0x100, make_small_operand(1), DebugVerbosity::None)?
    );

    assert_eq!(
        (Action::SetWindow(WindowLayout::Lower, 0x100), None),
        set_window(0x100, make_small_operand(0), DebugVerbosity::None)?
    );

    Ok(())
}

///
/// Set the input stream
///
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#input_stream>
///  
///
pub fn input_stream(
    pc_addr: usize,
    operand: Operand,
    verbosity: DebugVerbosity,
    version: ZCodeVersion,
) -> Result<(Action, Option<String>), ZmachineError> {
    match version {
        ZCodeVersion::V1 | ZCodeVersion::V2 => {
            return Err(ZmachineError::InstructionsUnsupportedInputStream())
        }
        _ => (),
    }

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("input_stream", &[operand])),
    };

    let stream_number = operand.operand_value;
    if stream_number > 1 {
        return Err(ZmachineError::InstructionsUnsupportedInputStream());
    }

    if stream_number == 0 {
        Ok((
            Action::SwitchInputStream(InputStreamEnum::Keyboard, pc_addr),
            instruction_text,
        ))
    } else {
        Ok((
            Action::SwitchInputStream(InputStreamEnum::File, pc_addr),
            instruction_text,
        ))
    }
}

#[test]
fn test_input_stream() -> Result<(), ZmachineError> {
    assert_eq!(
        Err(ZmachineError::InstructionsUnsupportedInputStream()),
        input_stream(
            0x100,
            make_small_operand(3),
            DebugVerbosity::None,
            ZCodeVersion::V1
        )
    );

    assert_eq!(
        Err(ZmachineError::InstructionsUnsupportedInputStream()),
        input_stream(
            0x100,
            make_small_operand(3),
            DebugVerbosity::None,
            ZCodeVersion::V2
        )
    );

    assert_eq!(
        Err(ZmachineError::InstructionsUnsupportedInputStream()),
        input_stream(
            0x100,
            make_small_operand(3),
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    assert_eq!(
        Ok((
            Action::SwitchInputStream(InputStreamEnum::Keyboard, 0x100),
            None
        )),
        input_stream(
            0x100,
            make_small_operand(0),
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    assert_eq!(
        Ok((
            Action::SwitchInputStream(InputStreamEnum::File, 0x100),
            None
        )),
        input_stream(
            0x100,
            make_small_operand(1),
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    Ok(())
}

///
/// Toggle an output stream
///
/// See: <https://www.inform-fiction.org/zmachine/standards/z1point1/sect15.html#output_stream>
///  
///
pub fn output_stream(
    pc_addr: usize,
    operands: Vec<Operand>,
    verbosity: DebugVerbosity,
    _version: ZCodeVersion,
) -> Result<(Action, Option<String>), ZmachineError> {
    if operands.is_empty() {
        return Err(ZmachineError::InstructionsExpected2Operands());
    }

    let instruction_text = match verbosity {
        DebugVerbosity::None => None,
        _ => Some(make_instruction_text("output_stream", &operands)),
    };

    let stream_number = word_to_signed(operands[0].operand_value);
    let toggle = stream_number > 0;

    match stream_number.abs() {
        0 => Ok((Action::Nop(pc_addr), instruction_text)),
        1 => Ok((
            Action::SetOutputStream(OutputStreamEnum::Screen, None, toggle, pc_addr),
            instruction_text,
        )),
        2 => Ok((
            Action::SetOutputStream(OutputStreamEnum::Transcript, None, toggle, pc_addr),
            instruction_text,
        )),
        3 => {
            // Memory stream requires another parameter, address of table is required
            if toggle {
                if operands.len() != 2 {
                    Err(ZmachineError::InstructionsExpected3Operands())
                } else {
                    Ok((
                        Action::SetOutputStream(
                            OutputStreamEnum::Memory,
                            Some(operands[1].operand_value),
                            true,
                            pc_addr,
                        ),
                        instruction_text,
                    ))
                }
            } else {
                Ok((
                    Action::SetOutputStream(OutputStreamEnum::Memory, None, false, pc_addr),
                    instruction_text,
                ))
            }
        }
        4 => Ok((
            Action::SetOutputStream(OutputStreamEnum::Commands, None, toggle, pc_addr),
            instruction_text,
        )),
        _ => Err(ZmachineError::InstructionsUnsupportedOutputStream()),
    }
}

#[test]
fn test_output_stream() -> Result<(), ZmachineError> {
    assert_eq!(
        Err(ZmachineError::InstructionsUnsupportedOutputStream()),
        output_stream(
            0x100,
            vec![make_large_operand(5)],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    assert_eq!(
        Err(ZmachineError::InstructionsUnsupportedOutputStream()),
        output_stream(
            0x100,
            vec![make_large_operand(signed_to_word(-5))],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    assert_eq!(
        Ok((
            Action::SetOutputStream(OutputStreamEnum::Screen, None, true, 0x100),
            None
        )),
        output_stream(
            0x100,
            vec![make_large_operand(signed_to_word(1))],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    assert_eq!(
        Ok((
            Action::SetOutputStream(OutputStreamEnum::Screen, None, false, 0x100),
            None
        )),
        output_stream(
            0x100,
            vec![make_large_operand(signed_to_word(-1))],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    assert_eq!(
        Ok((
            Action::SetOutputStream(OutputStreamEnum::Screen, None, true, 0x100),
            None
        )),
        output_stream(
            0x100,
            vec![make_large_operand(signed_to_word(1))],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    assert_eq!(
        Ok((
            Action::SetOutputStream(OutputStreamEnum::Commands, None, false, 0x100),
            None
        )),
        output_stream(
            0x100,
            vec![make_large_operand(signed_to_word(-4))],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    assert_eq!(
        Ok((
            Action::SetOutputStream(OutputStreamEnum::Commands, None, true, 0x100),
            None
        )),
        output_stream(
            0x100,
            vec![make_large_operand(signed_to_word(4))],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    assert_eq!(
        Ok((
            Action::SetOutputStream(OutputStreamEnum::Transcript, None, false, 0x100),
            None
        )),
        output_stream(
            0x100,
            vec![make_large_operand(signed_to_word(-2))],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    assert_eq!(
        Err(ZmachineError::InstructionsExpected3Operands()),
        output_stream(
            0x100,
            vec![make_large_operand(signed_to_word(3))],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    assert_eq!(
        Ok((
            Action::SetOutputStream(OutputStreamEnum::Memory, Some(0x1234), true, 0x100),
            None
        )),
        output_stream(
            0x100,
            vec![
                make_large_operand(signed_to_word(3)),
                make_large_operand(0x1234)
            ],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    assert_eq!(
        Ok((
            Action::SetOutputStream(OutputStreamEnum::Memory, None, false, 0x100),
            None
        )),
        output_stream(
            0x100,
            vec![make_large_operand(signed_to_word(-3))],
            DebugVerbosity::None,
            ZCodeVersion::V3
        )
    );

    Ok(())
}

///
/// Used for testing instuctions
///
///
/// Rust doesn't compile tests by default, and these functions are only used in tests, so you'll see
/// #[allow(dead_code)] on those
/// https://www.reddit.com/r/rust/comments/69bm0r/why_does_rust_warn_me_that_im_not_using_methods/

#[allow(dead_code)]
fn make_small_operand(val: u8) -> Operand {
    Operand {
        operand_value: val as u16,
        operand_type: OperandType::Small,
        variable_number: 0,
    }
}
#[allow(dead_code)]
fn make_large_operand(val: u16) -> Operand {
    Operand {
        operand_value: val,
        operand_type: OperandType::Large,
        variable_number: 0,
    }
}

struct StubV123MemoryObjectReader {
    memory: Vec<u8>,
    variables: Vec<u16>,
}

impl StubV123MemoryObjectReader {
    #[allow(dead_code)]
    pub fn set_variable(&mut self, variable_number: u8, variable_val: u16) {
        self.variables[variable_number as usize] = variable_val;
    }

    #[allow(dead_code)]
    pub fn create() -> StubV123MemoryObjectReader {
        StubV123MemoryObjectReader {
            memory: vec![0x11, 0x11, 0x11, 0x12, 0x34, 0x56, 0x78, 0x01],
            variables: vec![0; 255],
        }
    }

    #[allow(dead_code)]
    pub fn create_with_memory(memory: Vec<u8>) -> StubV123MemoryObjectReader {
        StubV123MemoryObjectReader {
            memory,
            variables: vec![0; 255],
        }
    }

    #[allow(dead_code)]
    pub fn create_with_memory_and_variables(
        memory: Vec<u8>,
        variables: Vec<u16>,
    ) -> StubV123MemoryObjectReader {
        StubV123MemoryObjectReader { memory, variables }
    }
}

// Test object tree reader is all hard coded
// Object 1 had children 2 and 3 and 4
impl ObjectTreeReader for StubV123MemoryObjectReader {
    fn get_attribute(&self, obj: usize, attribute: u8) -> std::result::Result<bool, ZmachineError> {
        if obj == 2 && attribute == 3 {
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn get_child(&self, obj: usize) -> std::result::Result<usize, ZmachineError> {
        if obj == 1 {
            Ok(2)
        } else {
            Ok(0)
        }
    }
    fn get_property_address(
        &self,
        obj: usize,
        attribute: usize,
    ) -> std::result::Result<usize, ZmachineError> {
        if obj == 2 && attribute == 3 {
            Ok(0x1234)
        } else {
            Ok(0)
        }
    }
    fn get_short_name(
        &mut self,
        object_number: usize,
    ) -> std::result::Result<std::string::String, ZmachineError> {
        Ok(format!("Object {}", object_number))
    }
    fn get_sibling(&self, obj: usize) -> std::result::Result<usize, ZmachineError> {
        if obj == 2 {
            Ok(3)
        } else if obj == 3 {
            Ok(4)
        } else {
            Ok(0)
        }
    }
    fn get_parent(&self, obj: usize) -> std::result::Result<usize, ZmachineError> {
        if obj == 2 || obj == 3 || obj == 4 {
            Ok(1)
        } else {
            Ok(0)
        }
    }
    fn get_next_property(
        &self,
        obj: usize,
        property: usize,
    ) -> std::result::Result<usize, ZmachineError> {
        if obj == 2 && property == 0 {
            Ok(2)
        } else if obj == 2 && property == 2 {
            Ok(3)
        } else {
            Ok(0)
        }
    }
    fn get_property(
        &self,
        object: usize,
        property: usize,
    ) -> std::result::Result<Property, ZmachineError> {
        if object == 1 && property == 2 {
            Ok(Property {
                object,
                property,
                value: 0xff,
                size: 1,
                start_address: 0xfff,
            })
        } else if object == 1 && property == 3 {
            Ok(Property {
                object,
                property,
                value: 0xffff,
                size: 2,
                start_address: 0xfff,
            })
        } else if object == 1 && property == 4 {
            Ok(Property {
                object,
                property,
                value: 0xff_ffff,
                size: 3,
                start_address: 0xfff,
            })
        } else {
            Err(ZmachineError::ObjectInvalidProperty(property))
        }
    }

    fn get_property_length(&self, addr: usize) -> std::result::Result<usize, ZmachineError> {
        if addr == 0x1234 {
            Ok(0x4321)
        } else {
            Ok(0)
        }
    }
}

impl MemoryReader for StubV123MemoryObjectReader {
    // Return the byte at address, with error if read is outside of bounds
    fn get_byte(&self, address: usize) -> Result<u8, ZmachineError> {
        Ok(self.memory[address])
    }

    // Return a vector of length bytes starting at address
    fn get_bytes(&self, _address: usize, _length: usize) -> Result<Vec<u8>, ZmachineError> {
        Ok(Vec::new())
    }

    // Return the specified bit at the address. Bit 0 is the rightmost (least significant)
    fn get_bit(&self, address: usize, bit: u8) -> Result<bool, ZmachineError> {
        Ok((self.memory[address] >> bit) & 0x01 == 1)
    }

    // Return the word at address, with error if read is outside of bounds
    fn get_word(&self, address: usize) -> Result<u16, ZmachineError> {
        Ok((self.memory[address] as u16) << 8 | (self.memory[address + 1] as u16))
    }

    // Per 1.2.3, packed addreses are used for routines/strings. Varies based on version
    fn convert_packed_address(&self, address: u16) -> usize {
        (address * 2) as usize
    }

    fn get_variable(&mut self, variable: u8) -> std::result::Result<u16, ZmachineError> {
        Ok(self.variables[variable as usize])
    }

    fn peek_variable(
        &self,
        variable: u8,
        _ignore_locals: bool,
    ) -> std::result::Result<u16, ZmachineError> {
        Ok(self.variables[variable as usize])
    }
    fn get_word_bounds_check(&self, address: usize) -> std::result::Result<u16, ZmachineError> {
        self.get_word(address)
    }
    fn get_byte_bounds_check(&self, address: usize) -> std::result::Result<u8, ZmachineError> {
        self.get_byte(address)
    }

    fn get_stack_pointer(&self) -> usize {
        0
    }
    fn verify_checksum(&self, _: u16) -> std::result::Result<bool, ZmachineError> {
        Ok(true)
    }
}
