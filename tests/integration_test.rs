extern crate zmachine;

use rand::Rng;
use std::fs;
use std::path::PathBuf;
use zmachine::instructions::{
    handle_instruction, Action, DebugVerbosity, InputStreamEnum, MemoryReader, ObjectTreeReader,
    OutputStreamEnum, WindowLayout, ZCodeVersion, ZmachineError, BYTE_LENGTH, WORD_LENGTH,
};
use zmachine::quetzal::iff::{
    get_chunk_id_as_str, load_iff_chunks_from_bytes, save_iff_chunks_to_bytes, IffChunk,
};

use zmachine::interfaces::{DebugIO, TerpIO};
use zmachine::story::{
    StatusMode, ZCharacterMapper, ZCharacterMapperV1, ZCharacterMapperV2, ZCharacterMapperV3,
    ABBREV_1, ABBREV_2, ABBREV_3, NOPRINT_CHAR, TOGGLE_EXTENDED,
};
use zmachine::vm::{
    compress_story_data, load_compressed_save_data, DictionaryWord, VMLoadError, VMState, GLOBAL_1,
    GLOBAL_2, GLOBAL_3, OBJECT_NOTHING, VM,
};

#[derive(Copy, Clone)]
enum TestStory {
    Basic,
    Basic2,
    Basic3,
}

fn load_test_story_data(story: TestStory) -> Vec<u8> {
    // thanks to https://stackoverflow.com/questions/30003921/how-can-i-locate-resources-for-testing-with-cargo
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("resources");
    d.push("stories");

    match story {
        TestStory::Basic => {
            d.push("basic.z3");
        }
        TestStory::Basic2 => {
            d.push("basic_2.z3");
        }
        TestStory::Basic3 => {
            d.push("basic_3.z3");
        }
    }

    fs::read(d.as_os_str()).expect("Error loading test story file 'basic.z3'.")
}

fn load_test_story_data_v2(story: TestStory) -> Vec<u8> {
    // Force version 2 by tweakin the header byte
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("resources");
    d.push("stories");

    match story {
        TestStory::Basic => {
            d.push("basic.z3");
        }
        TestStory::Basic2 => {
            d.push("basic_2.z3");
        }
        TestStory::Basic3 => {
            d.push("basic_3.z3");
        }
    }

    let mut v = fs::read(d.as_os_str()).expect("Error loading test story file 'basic.z3'.");
    v[0] = 2; // Version byte
    v
}

#[test]
fn test_basic_instructions() -> Result<(), ZmachineError> {
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic), true, false)
        .expect("Error loading story");
    let version = vm.get_version();

    // Magic numbers below all correspond to specific addresses in basic.z3
    // Used the txd tool (https://www.inform-fiction.org/zmachine/ztools.html) to extract these
    assert_eq!(
        (Action::Quit(), None),
        handle_instruction(0x049c, &mut vm, version, DebugVerbosity::None)
            .expect("Unknown instruction")
    );

    assert_eq!(
        (Action::Return(1), None),
        handle_instruction(0x04aa, &mut vm, version, DebugVerbosity::None)
            .expect("Unknown instruction")
    );
    assert_eq!(
        (Action::Return(0), None),
        handle_instruction(0x04b1, &mut vm, version, DebugVerbosity::None)
            .expect("Unknown instruction")
    );

    assert_eq!(
        (Action::PrintAddress(0x4a0, 0, false, false), None),
        handle_instruction(0x049f, &mut vm, version, DebugVerbosity::None)
            .expect("Unknown instruction")
    );

    assert_eq!(
        (Action::Call(0x049e, 0, 0, 0, 0, 0xff, 1180), None),
        handle_instruction(0x0497, &mut vm, version, DebugVerbosity::None)
            .expect("Unknown instruction")
    );

    Ok(())
}

fn load_czech() -> Vec<u8> {
    // Load the czech unit tests
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("resources");
    d.push("czech_0_8");
    d.push("czech.z3");

    fs::read(d.as_os_str()).expect("Error loading test story file 'czech.v3'.")
}

#[test]
fn test_memory() -> Result<(), ZmachineError> {
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic), true, false)
        .expect("Error loading story");

    // Use known header bytes to check read
    assert_eq!(0x03, vm.get_byte(0)?);
    assert_eq!(0x20, vm.get_byte(1)?);
    assert_eq!(0x00, vm.get_byte(2)?);
    assert_eq!(0x01, vm.get_byte(3)?);

    assert_eq!(0x0320, vm.get_word(0)?);
    assert_eq!(0x0001, vm.get_word(2)?);

    assert_eq!(vec![0x03, 0x20, 0x00], vm.get_bytes(0, 3)?);
    assert_eq!(vec![0x00, 0x01], vm.get_bytes(2, 2)?);

    vm.set_word(0x100, 0x1234)?;
    vm.set_byte(0x102, 0x56)?;
    vm.set_bytes(0x103, vec![0x78, 0x90])?;

    assert_eq!(vec![0x12, 0x34, 0x56, 0x78, 0x90], vm.get_bytes(0x100, 5)?);

    Ok(())
}

#[test]
// Test the exposed values on the default story
fn test_story_values() -> Result<(), ZmachineError> {
    let vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic), true, false)
        .expect("Error loading story");
    assert_eq!(vm.get_version(), ZCodeVersion::V3);
    assert_eq!(vm.get_status_mode(), StatusMode::Score);
    assert_eq!(vm.get_file_length(), 0x04f6);
    assert_eq!(vm.get_checksum(), 0x4744);
    assert_eq!(vm.get_release_number(), 1);
    assert_eq!(vm.get_inform_version(), "6.31");
    assert_eq!(vm.get_serial(), "200412");

    Ok(())
}

#[test]
fn test_load_error_version() -> Result<(), ZmachineError> {
    for i in 0..254 {
        let mut data = load_test_story_data(TestStory::Basic);
        data[0] = i;
        // Versions 1,2,3 supported so load should succeed
        let should_succeed = i == 1 || i == 2 || i == 3;

        match VM::create_from_story_bytes(data, true, false) {
            Err(_) => {
                assert!(
                    !should_succeed,
                    "Expected success for version {}, got failure.",
                    i
                );
            }
            Ok(_) => {
                assert!(
                    should_succeed,
                    "Expected success for version {}, got failure.",
                    i
                );
            }
        }
    }

    Ok(())
}

#[test]
fn test_load_error_checksum() -> Result<(), ZmachineError> {
    let mut data = load_test_story_data(TestStory::Basic);
    data[0x100] = 0xff;

    match VM::create_from_story_bytes(data, true, false) {
        Err(m) => {
            assert_eq!(m, VMLoadError::ChecksumMismatch());
        }
        Ok(_) => {
            panic!("Should have failed with checksum error.");
        }
    }

    Ok(())
}

#[test]
fn test_load_error_length() -> Result<(), ZmachineError> {
    let mut data = load_test_story_data(TestStory::Basic);
    let target_len = (1024 * 128) + 2;
    data.resize(target_len, 0x01);

    match VM::create_from_story_bytes(data, true, false) {
        Err(m) => {
            assert_eq!(m, VMLoadError::StoryFileTooLarge(target_len));
        }
        Ok(_) => {
            panic!("Should have failed with length error.");
        }
    }

    Ok(())
}

#[test]
fn test_status_line_flag() -> Result<(), ZmachineError> {
    let data = load_test_story_data(TestStory::Basic);
    assert_eq!(
        VM::create_from_story_bytes(data, true, false)
            .expect("Error loading story")
            .get_status_mode(),
        StatusMode::Score
    );
    let mut data = load_test_story_data(TestStory::Basic);
    data[0x01] = 0x02; // set second bit of flag 1
    assert_eq!(
        VM::create_from_story_bytes(data, true, false)
            .expect("Error loading story")
            .get_status_mode(),
        StatusMode::Time
    );

    Ok(())
}

#[test]
fn test_word_address() -> Result<(), ZmachineError> {
    let vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic), true, false)
        .expect("Error loading story");
    assert_eq!(vm.convert_word_address(0), 0);
    assert_eq!(vm.convert_word_address(1), 2);
    assert_eq!(vm.convert_word_address(10), 20);

    Ok(())
}

#[test]
fn test_packed_address_v1() -> Result<(), ZmachineError> {
    let mut data = load_test_story_data(TestStory::Basic);
    data[0] = 1;
    let vm = VM::create_from_story_bytes(data, true, false).expect("Error loading story");
    assert_eq!(vm.convert_packed_address(0), 0);
    assert_eq!(vm.convert_packed_address(1), 2);
    assert_eq!(vm.convert_packed_address(10), 20);

    Ok(())
}

#[test]
fn test_packed_address_v2() -> Result<(), ZmachineError> {
    let mut data = load_test_story_data(TestStory::Basic);
    data[0] = 2;
    let vm = VM::create_from_story_bytes(data, true, false).expect("Error loading story");
    assert_eq!(vm.convert_packed_address(0), 0);
    assert_eq!(vm.convert_packed_address(1), 2);
    assert_eq!(vm.convert_packed_address(10), 20);

    Ok(())
}

#[test]
fn test_packed_address_v3() -> Result<(), ZmachineError> {
    let mut data = load_test_story_data(TestStory::Basic);
    data[0] = 3;
    let vm = VM::create_from_story_bytes(data, true, false).expect("Error loading story");
    assert_eq!(vm.convert_packed_address(0), 0);
    assert_eq!(vm.convert_packed_address(1), 2);
    assert_eq!(vm.convert_packed_address(10), 20);

    Ok(())
}

#[test]
fn test_is_readable() -> Result<(), ZmachineError> {
    let vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic), true, false)
        .expect("Error loading story");
    let static_top = vm.get_last_address();
    for addr in 0..static_top - 1 {
        // static address from header in file
        assert!(
            vm.is_readable(addr),
            "Readable address returned not readable."
        );
    }

    for addr in static_top..0xFFFF {
        assert!(
            !vm.is_readable(addr),
            "Unreadable address returned as readable."
        );
    }

    // Check can't read past 0xffff even if story file is that big

    Ok(())
}

#[test]
fn test_is_writeable() -> Result<(), ZmachineError> {
    let vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic), true, false)
        .expect("Error loading story");
    let static_base = 0x048C; // already know this address for the file
    let header_top = 0x20;

    for addr in 0..header_top - 1 {
        if addr == 0x10 {
            // Flags 2 byte is writeable by game
            assert!(
                vm.is_writeable(addr),
                "Flags 2 in header incorrectly returned not writeable"
            );
        } else {
            assert!(
                !vm.is_writeable(addr),
                "Header address incorrectly returned writeable"
            );
        }
    }

    for addr in header_top..static_base - 1 {
        assert!(
            vm.is_writeable(addr),
            "Writeable address returned as not writeable."
        );
    }

    for addr in static_base..vm.get_last_address() {
        assert!(
            !vm.is_writeable(addr),
            "Unwriteable address returned as writeable."
        );
    }

    // Test ranged version
    assert!(!vm.is_writeable_range(static_base, 1));

    assert!(vm.is_writeable_range(static_base - 1, 1));

    assert!(!vm.is_writeable_range(static_base, 2));
    assert!(vm.is_writeable_range(static_base - 2, 2));

    Ok(())
}

#[test]
// test getting/setting variables
// 0 = stack
// 1-15 = local
// 16-255 = global
// This test indirectly tests routine setup with locals and call arguments
fn test_variables() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic), true, false)
        .expect("Error loading story");

    // Test stack
    vm.set_variable(0, 1)?;
    vm.set_variable(0, 2)?;

    assert_eq!(2, vm.get_variable(0)?);
    assert_eq!(1, vm.get_variable(0)?);
    assert_eq!(
        Err(ZmachineError::MemoryStackOverflowRoutine()),
        vm.get_variable(0)
    );

    vm.set_variable(0, 1)?;

    // Set up a new routine with 15 local variables to test locals and stack
    vm.set_byte(0x100, 0x0f)?;

    for i in 1..16 {
        if i > 3 {
            vm.set_word(0x101 + ((i - 1) * WORD_LENGTH), i as u16)?;
        } else {
            // These defaults should be overwritten by call arguments
            vm.set_word(0x101 + ((i - 1) * WORD_LENGTH), 0)?;
        }
    }
    vm.handle_action(Action::Call(0x100, 3, 1, 2, 3, 0, 0), &mut io);

    // Now in new routine, so previous stack should be empty
    vm.set_variable(0, 2)?;
    assert_eq!(2, vm.get_variable(0)?);
    assert_eq!(
        Err(ZmachineError::MemoryStackOverflowRoutine()),
        vm.get_variable(0)
    );

    // Locals -- should have been pre-set by routine call
    for i in 1..16 {
        assert_eq!(i as u16, vm.get_variable(i as u8)?);
        vm.set_variable(i as u8, i + 1)?;
        assert_eq!(i + 1, vm.get_variable(i as u8)?);
    }

    // Globals
    for i in 16..255 {
        vm.set_variable(i as u8, i + 1)?;
        assert_eq!(i + 1, vm.get_variable(i as u8)?);

        // validate direct memory access. Magic number is based on data in story file.
        vm.set_word(0x02AC + ((i - 16) as usize * WORD_LENGTH) as usize, i)?;
        assert_eq!(i as u16, vm.get_variable(i as u8)?);
    }

    // Return from routine. Main routine has no locals, so get/set should throw access error
    vm.handle_action(Action::Return(1), &mut io);

    for i in 1..16 {
        assert_eq!(
            Err(ZmachineError::MemoryInvalidLocalVariable(i)),
            vm.get_variable(i as u8)
        );
        assert_eq!(
            Err(ZmachineError::RoutineLocalVariableOutOfBounds(i as usize)),
            vm.set_variable(i as u8, 0)
        );
    }

    Ok(())
}

#[test]
fn test_status_line_score() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    // Global 1 is room

    vm.set_variable(GLOBAL_1, OBJECT_TEST_PARENT as u16)?;
    vm.set_variable(GLOBAL_2, 65535)?; // Should be -1
    vm.set_variable(GLOBAL_3, 51)?;
    vm.refresh_status(&mut io);
    assert_eq!("A Test Parent", io.status_left);
    assert_eq!("-1/51", io.status_right);
    Ok(())
}

#[test]
fn test_status_line_time() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut data = load_test_story_data(TestStory::Basic2);
    data[1] = 0xff; // Set flag 1 on flags 1 to true to get time mode
    let mut vm = VM::create_from_story_bytes(data, false, false).expect("Error loading story");

    // Global 1 is room
    vm.set_variable(GLOBAL_1, OBJECT_TEST_CHILD as u16)?;
    vm.set_variable(GLOBAL_2, 18)?;
    vm.set_variable(GLOBAL_3, 3)?;
    vm.refresh_status(&mut io);
    assert_eq!("A Test Child", io.status_left);
    assert_eq!("18:03", io.status_right);

    Ok(())
}

const OBJECT_CLASS: usize = 1;
const OBJECT_OBJECT: usize = 2;
const OBJECT_ROUTINE: usize = 3;
const OBJECT_STRING: usize = 4;
const OBJECT_TEST_PARENT: usize = 5;
const OBJECT_TEST_CHILD: usize = 6;
const OBJECT_TEST_SIBLING: usize = 7;
const OBJECT_TEST_TEXT: usize = 8;
const OBJECT_TEST_UNICODE: usize = 9;
const OBJECT_TEST_EMPTY: usize = 10;

#[test]
#[allow(clippy::cognitive_complexity)]
fn test_object_tree_basic_2() -> Result<(), ZmachineError> {
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");
    assert_eq!(10, vm.guess_last_object());

    assert_eq!(vm.get_short_name(OBJECT_CLASS)?, "Class");
    assert_eq!(OBJECT_NOTHING, vm.get_parent(OBJECT_CLASS)?);
    assert_eq!(OBJECT_NOTHING, vm.get_sibling(OBJECT_CLASS)?);
    assert_eq!(OBJECT_NOTHING, vm.get_child(OBJECT_CLASS)?);

    assert_eq!(vm.get_short_name(OBJECT_OBJECT)?, "Object");
    assert_eq!(OBJECT_NOTHING, vm.get_parent(OBJECT_OBJECT)?);
    assert_eq!(OBJECT_NOTHING, vm.get_sibling(OBJECT_OBJECT)?);
    assert_eq!(OBJECT_NOTHING, vm.get_child(OBJECT_OBJECT)?);

    assert_eq!(vm.get_short_name(OBJECT_ROUTINE)?, "Routine");
    assert_eq!(OBJECT_NOTHING, vm.get_parent(OBJECT_ROUTINE)?);
    assert_eq!(OBJECT_NOTHING, vm.get_sibling(OBJECT_ROUTINE)?);
    assert_eq!(OBJECT_NOTHING, vm.get_child(OBJECT_ROUTINE)?);

    assert_eq!(vm.get_short_name(OBJECT_STRING)?, "String");
    assert_eq!(OBJECT_NOTHING, vm.get_parent(OBJECT_STRING)?);
    assert_eq!(OBJECT_NOTHING, vm.get_sibling(OBJECT_STRING)?);
    assert_eq!(OBJECT_NOTHING, vm.get_child(OBJECT_STRING)?);

    // Expected default properties for this file. Set one so we can test it
    vm.set_word(0x0110, 55)?; // Address is hard coded for this file

    let expected_defaults = vec![
        55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,
    ];
    #[allow(clippy::needless_range_loop)]
    for i in 0..31 {
        assert_eq!(vm.get_default_property(i + 1)?, expected_defaults[i]);
    }

    // Parent should have no attributes or default properties
    for i in 0..32 {
        assert!(!vm.get_attribute(OBJECT_TEST_PARENT, i)?);
    }

    assert_eq!(vm.get_short_name(OBJECT_TEST_PARENT)?, "A Test Parent");

    // Parent has no propreties
    assert_eq!(0, vm.get_next_property(OBJECT_TEST_PARENT, 1)?);
    assert_eq!(0, vm.get_property_address(OBJECT_TEST_PARENT, 2)?);
    assert_eq!(0, vm.get_property_address(OBJECT_TEST_PARENT, 3)?);

    // Should return default if no property
    //assert_eq!(55, vm.get_property(OBJECT_TEST_PARENT, 1)?.value);
    assert_eq!(0, vm.get_property(OBJECT_TEST_PARENT, 2)?.value);
    assert_eq!(
        expected_defaults[4] as usize,
        vm.get_property(OBJECT_TEST_PARENT, 5)?.value
    );

    assert_eq!(OBJECT_NOTHING, vm.get_parent(OBJECT_TEST_PARENT)?);
    assert_eq!(OBJECT_NOTHING, vm.get_sibling(OBJECT_TEST_PARENT)?);
    assert_eq!(OBJECT_TEST_CHILD, vm.get_child(OBJECT_TEST_PARENT)?);

    assert_eq!(vm.get_short_name(OBJECT_TEST_CHILD)?, "A Test Child");

    // Child has 7,15,23,31
    for i in 0..32 {
        if i == 7 || i == 15 || i == 23 || i == 31 {
            assert!(vm.get_attribute(OBJECT_TEST_CHILD, i)?);
        } else {
            assert!(!vm.get_attribute(OBJECT_TEST_CHILD, i)?);
        }
    }

    // Child has two properties 3 and 1
    assert_eq!(0, vm.get_next_property(OBJECT_TEST_CHILD, 1)?);

    let property = vm.get_property(OBJECT_TEST_CHILD, 3)?;
    assert_eq!(OBJECT_TEST_CHILD, property.object);
    assert_eq!(3, property.property);
    assert_eq!(2, property.size);
    assert_eq!(514, property.start_address); // address in story file
    assert_eq!(0x0435, property.value);
    assert_eq!(504, vm.get_properties_address(OBJECT_TEST_CHILD)?);
    assert_eq!(514, vm.get_property_address(OBJECT_TEST_CHILD, 3)?);
    assert_eq!(
        2,
        vm.get_property_length(vm.get_property_address(OBJECT_TEST_CHILD, 3)?)?
    );

    let property = vm.get_property(OBJECT_TEST_CHILD, 1)?;
    assert_eq!(OBJECT_TEST_CHILD, property.object);
    assert_eq!(1, property.property);
    assert_eq!(6, property.size);
    assert_eq!(517, property.start_address); // address in story file
    assert_eq!(0x062C_0633_063A, property.value);
    assert_eq!(517, vm.get_property_address(OBJECT_TEST_CHILD, 1)?);
    assert_eq!(
        6,
        vm.get_property_length(vm.get_property_address(OBJECT_TEST_CHILD, 1)?)?
    );

    assert_eq!(OBJECT_TEST_PARENT, vm.get_parent(OBJECT_TEST_CHILD)?);
    assert_eq!(OBJECT_TEST_SIBLING, vm.get_sibling(OBJECT_TEST_CHILD)?);
    assert_eq!(OBJECT_NOTHING, vm.get_child(OBJECT_TEST_CHILD)?);

    assert_eq!(
        vm.get_short_name(OBJECT_TEST_SIBLING)?,
        "A Test Sib [X] ling"
    );

    // Sibling should have all attributes
    for i in 0..32 {
        assert!(vm.get_attribute(OBJECT_TEST_SIBLING, i)?);
    }

    // Sibling has one property (3)
    assert_eq!(3, vm.get_next_property(OBJECT_TEST_SIBLING, 0)?);
    assert_eq!(0, vm.get_next_property(OBJECT_TEST_SIBLING, 3)?);

    let property = vm.get_property(OBJECT_TEST_SIBLING, 3)?;
    assert_eq!(OBJECT_TEST_SIBLING, property.object);
    assert_eq!(3, property.property);
    assert_eq!(2, property.size);
    assert_eq!(542, property.start_address);
    assert_eq!(0x043C, property.value);
    assert_eq!(524, vm.get_properties_address(OBJECT_TEST_SIBLING)?);
    assert_eq!(0, vm.get_property_address(OBJECT_TEST_SIBLING, 1)?);
    assert_eq!(542, vm.get_property_address(OBJECT_TEST_SIBLING, 3)?);

    assert_eq!(OBJECT_TEST_PARENT, vm.get_parent(OBJECT_TEST_SIBLING)?);
    assert_eq!(OBJECT_TEST_TEXT, vm.get_sibling(OBJECT_TEST_SIBLING)?);
    assert_eq!(OBJECT_NOTHING, vm.get_child(OBJECT_TEST_SIBLING)?);

    Ok(())
}

#[test]
#[allow(clippy::cognitive_complexity)]
fn test_object_tree_manipulate() -> Result<(), ZmachineError> {
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");
    // Test setting properties
    assert_eq!(0xffcc, vm.set_property(OBJECT_TEST_SIBLING, 3, 0xffcc)?);
    let property = vm.get_property(OBJECT_TEST_SIBLING, 3)?;
    assert_eq!(3, property.property);
    assert_eq!(2, property.size);
    assert_eq!(542, property.start_address);
    assert_eq!(0xffcc, property.value);

    // Tweak property to size 1, try again
    vm.set_byte(property.start_address - BYTE_LENGTH, 3)?; // Size byte is size + property
    assert_eq!(0x00cc, vm.set_property(OBJECT_TEST_SIBLING, 3, 0xffcc)?);
    let property = vm.get_property(OBJECT_TEST_SIBLING, 3)?;
    assert_eq!(3, property.property);
    assert_eq!(1, property.size);
    assert_eq!(542, property.start_address);
    assert_eq!(0x00cc, property.value);

    // Error if property is bigger
    assert_eq!(
        Err(ZmachineError::ObjectInvalidPropertySize(6)),
        vm.set_property(OBJECT_TEST_CHILD, 1, 0xfff)
    );

    // Structure is 1,2,3,4
    // Parent (5)
    //    |
    //  Child (6) -> Sibling (7) -> Text (8) -> Unicode (9) -> Empty (10)
    assert_eq!("[1: P0 C0 S0][2: P0 C0 S0][3: P0 C0 S0][4: P0 C0 S0][5: P0 C6 S0][6: P5 C0 S7][7: P5 C0 S8][8: P5 C0 S9][9: P5 C0 S10][10: P5 C0 S0]", vm.dump_objects(OBJECT_TEST_EMPTY).as_str());

    // Test an insert with no pre-existing children
    vm.insert_object(OBJECT_TEST_UNICODE, OBJECT_TEST_TEXT)?;
    assert_eq!("[1: P0 C0 S0][2: P0 C0 S0][3: P0 C0 S0][4: P0 C0 S0][5: P0 C6 S0][6: P5 C0 S7][7: P5 C0 S8][8: P5 C9 S10][9: P8 C0 S0][10: P5 C0 S0]", vm.dump_objects(OBJECT_TEST_EMPTY).as_str());

    // Re-insert shouldn't change anything
    vm.insert_object(OBJECT_TEST_UNICODE, OBJECT_TEST_TEXT)?;
    assert_eq!("[1: P0 C0 S0][2: P0 C0 S0][3: P0 C0 S0][4: P0 C0 S0][5: P0 C6 S0][6: P5 C0 S7][7: P5 C0 S8][8: P5 C9 S10][9: P8 C0 S0][10: P5 C0 S0]", vm.dump_objects(OBJECT_TEST_EMPTY).as_str());

    // Test an insert with an existing child
    vm.insert_object(OBJECT_TEST_SIBLING, OBJECT_TEST_TEXT)?;
    assert_eq!("[1: P0 C0 S0][2: P0 C0 S0][3: P0 C0 S0][4: P0 C0 S0][5: P0 C6 S0][6: P5 C0 S8][7: P8 C0 S9][8: P5 C7 S10][9: P8 C0 S0][10: P5 C0 S0]", vm.dump_objects(OBJECT_TEST_EMPTY).as_str());

    // Parent (5)
    //    |
    //  Child (6) -> Text (8) ->  Empty (10)
    //                 |
    //                Sibling (7) ->  Unicode (9)
    // Test insert with 2 existing children
    vm.insert_object(OBJECT_TEST_EMPTY, OBJECT_TEST_TEXT)?;
    assert_eq!("[1: P0 C0 S0][2: P0 C0 S0][3: P0 C0 S0][4: P0 C0 S0][5: P0 C6 S0][6: P5 C0 S8][7: P8 C0 S9][8: P5 C10 S0][9: P8 C0 S0][10: P8 C0 S7]", vm.dump_objects(OBJECT_TEST_EMPTY).as_str());

    // Parent (5)
    //    |
    //  Child (6) -> Text (8)
    //                 |
    //               Empty (10) -> Sibling (7) ->  Unicode (9)

    // Move Empty to Child, then back. Should leave structure unchanged

    vm.insert_object(OBJECT_TEST_EMPTY, OBJECT_TEST_CHILD)?;
    vm.insert_object(OBJECT_TEST_EMPTY, OBJECT_TEST_TEXT)?;
    assert_eq!("[1: P0 C0 S0][2: P0 C0 S0][3: P0 C0 S0][4: P0 C0 S0][5: P0 C6 S0][6: P5 C0 S8][7: P8 C0 S9][8: P5 C10 S0][9: P8 C0 S0][10: P8 C0 S7]", vm.dump_objects(OBJECT_TEST_EMPTY).as_str());

    // Parent (5)
    //    |
    //  Child (6) -> Text (8)
    //                 |
    //               Empty (10) -> Sibling (7) ->  Unicode (9)

    // Remove first child
    vm.remove_object(OBJECT_TEST_CHILD)?;
    assert_eq!("[1: P0 C0 S0][2: P0 C0 S0][3: P0 C0 S0][4: P0 C0 S0][5: P0 C8 S0][6: P0 C0 S0][7: P8 C0 S9][8: P5 C10 S0][9: P8 C0 S0][10: P8 C0 S7]", vm.dump_objects(OBJECT_TEST_EMPTY).as_str());
    // Parent (5)
    //    |
    // Text (8)
    //    |
    // Empty (10) -> Sibling (7) ->  Unicode (9)

    // Remove Middle
    vm.remove_object(OBJECT_TEST_SIBLING)?;
    assert_eq!("[1: P0 C0 S0][2: P0 C0 S0][3: P0 C0 S0][4: P0 C0 S0][5: P0 C8 S0][6: P0 C0 S0][7: P0 C0 S0][8: P5 C10 S0][9: P8 C0 S0][10: P8 C0 S9]", vm.dump_objects(OBJECT_TEST_EMPTY).as_str());
    // Parent (5)
    //    |
    // Text (8)
    //    |
    // Empty (10) -> Unicode (9)

    // Remove end
    vm.remove_object(OBJECT_TEST_UNICODE)?;
    assert_eq!("[1: P0 C0 S0][2: P0 C0 S0][3: P0 C0 S0][4: P0 C0 S0][5: P0 C8 S0][6: P0 C0 S0][7: P0 C0 S0][8: P5 C10 S0][9: P0 C0 S0][10: P8 C0 S0]", vm.dump_objects(OBJECT_TEST_EMPTY).as_str());
    // Parent (5)
    //    |
    // Text (8)
    //    |
    // Empty (10)

    // Remove front
    vm.remove_object(OBJECT_TEST_EMPTY)?;
    assert_eq!("[1: P0 C0 S0][2: P0 C0 S0][3: P0 C0 S0][4: P0 C0 S0][5: P0 C8 S0][6: P0 C0 S0][7: P0 C0 S0][8: P5 C0 S0][9: P0 C0 S0][10: P0 C0 S0]", vm.dump_objects(OBJECT_TEST_EMPTY).as_str());

    // Parent (5)
    //    |
    // Text (8)

    // Add an object back from nothing
    vm.insert_object(OBJECT_TEST_EMPTY, OBJECT_TEST_TEXT)?;
    assert_eq!("[1: P0 C0 S0][2: P0 C0 S0][3: P0 C0 S0][4: P0 C0 S0][5: P0 C8 S0][6: P0 C0 S0][7: P0 C0 S0][8: P5 C10 S0][9: P0 C0 S0][10: P8 C0 S0]", vm.dump_objects(OBJECT_TEST_EMPTY).as_str());

    // Parent (5)
    //    |
    // Text (8)
    //    |
    // Empty (10)
    // Remove object with no parent shouldn't not fail
    vm.remove_object(OBJECT_TEST_PARENT)?;
    assert_eq!("[1: P0 C0 S0][2: P0 C0 S0][3: P0 C0 S0][4: P0 C0 S0][5: P0 C8 S0][6: P0 C0 S0][7: P0 C0 S0][8: P5 C10 S0][9: P0 C0 S0][10: P8 C0 S0]", vm.dump_objects(OBJECT_TEST_EMPTY).as_str());

    Ok(())
}

#[test]
fn test_ztext_v3() -> Result<(), ZmachineError> {
    // Use object descriptions to test ZText -- made it easy to generate text using inform
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");
    assert_eq!(
        vm.get_short_name(OBJECT_TEST_TEXT)?,
        "Aa Bb\nCc0Dd1Ee2Ff3Gg4Hh5Ii6Jj7Kk8Ll9Mm.Nn,Oo!Pp?Qq_Rr#Ss'Tt\"Uu/Vv\\Ww-Xx:Yy(Zz)"
    );
    assert_eq!(
        vm.get_short_name(OBJECT_TEST_UNICODE)?,
        "äöüÄÖÜß»«ëïÿËÏáéíóúýÁÉÍÓÚÝàèìòùÀÈÌÒÙâêîôûÂÊÎÔÛåÅøØãñõÃÑÕæÆçÇþðÞÐ£œŒ¡¿"
    );
    assert_eq!(vm.get_short_name(OBJECT_TEST_EMPTY)?, "");
    Ok(())
}

#[test]
#[allow(clippy::cognitive_complexity)]
fn test_property_bounds_errors() -> Result<(), ZmachineError> {
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert!(vm.calculate_object_address(0).is_err());
    assert!(vm.calculate_object_address(256).is_err());

    assert!(vm.get_properties_address(0).is_err());
    assert!(vm.get_properties_address(256).is_err());

    assert!(vm.get_property_address(0, 0).is_err());
    assert!(vm.get_property_address(256, 0).is_err());
    assert!(vm.get_property_address(1, 32).is_err());

    assert!(vm.get_short_name(0).is_ok());
    assert!(vm.get_short_name(256).is_err());

    assert!(vm.get_next_property(0, 0).is_err());
    assert!(vm.get_next_property(256, 0).is_err());
    assert!(vm.get_next_property(1, 32).is_err());

    assert!(vm.get_default_property(0).is_err());
    assert!(vm.get_default_property(32).is_err());

    assert!(vm.get_property(0, 0).is_err());
    assert!(vm.get_property(256, 0).is_err());
    assert!(vm.get_property(1, 0).is_err());
    assert!(vm.get_property(1, 32).is_err());

    assert!(vm.get_attribute(0, 0).is_ok());
    assert!(vm.get_attribute(256, 0).is_err());
    assert!(vm.get_attribute(1, 32).is_err());

    assert!(vm.get_parent(256).is_err());
    assert!(vm.get_parent(0).is_ok());

    assert!(vm.get_sibling(256).is_err());
    assert!(vm.get_sibling(0).is_ok());

    assert!(vm.get_child(256).is_err());
    assert!(vm.get_child(0).is_ok());

    Ok(())
}

#[test]
#[allow(clippy::cognitive_complexity)]
#[allow(clippy::char_lit_as_u8)]
fn test_z1_mapper() {
    let mut mapper = ZCharacterMapperV1::create();
    // 0 is always a space
    assert_eq!(' ' as u8, mapper.map(0));

    // 1 is newline
    assert_eq!('\n' as u8, mapper.map(1));

    // Test shifts. 8 will normally be a c. Shifted
    // up, will return C. Shifted down, will return 0.
    // Shift should only be for a single character
    assert_eq!('c' as u8, mapper.map(8));
    assert_eq!(NOPRINT_CHAR, mapper.map(2));
    assert_eq!('C' as u8, mapper.map(8));
    assert_eq!('c' as u8, mapper.map(8));

    // Shift down (3) will work the other way
    assert_eq!('c' as u8, mapper.map(8));
    assert_eq!(NOPRINT_CHAR, mapper.map(3));
    assert_eq!('1' as u8, mapper.map(8));
    assert_eq!('c' as u8, mapper.map(8));
    assert_eq!('i' as u8, mapper.map(14));

    // Test shift lock. These switch alphabets for all subsequent chars
    assert_eq!('c' as u8, mapper.map(8));
    assert_eq!(NOPRINT_CHAR, mapper.map(4));
    assert_eq!('C' as u8, mapper.map(8));
    assert_eq!('C' as u8, mapper.map(8));
    assert_eq!(NOPRINT_CHAR, mapper.map(5));
    assert_eq!('c' as u8, mapper.map(8));
    assert_eq!(NOPRINT_CHAR, mapper.map(5));
    assert_eq!('1' as u8, mapper.map(8));
    assert_eq!('1' as u8, mapper.map(8));
    assert_eq!(NOPRINT_CHAR, mapper.map(4));

    // 6 will return a, A, or space
    assert_eq!('a' as u8, mapper.map(6));
    assert_eq!(NOPRINT_CHAR, mapper.map(2));
    assert_eq!('A' as u8, mapper.map(6));
    assert_eq!(NOPRINT_CHAR, mapper.map(3));
    assert_eq!(' ' as u8, mapper.map(6));

    // 7 is a 0 in alphabet 2
    assert_eq!(NOPRINT_CHAR, mapper.map(5));
    assert_eq!('0' as u8, mapper.map(7));
}

#[test]
#[allow(clippy::cognitive_complexity)]
#[allow(clippy::char_lit_as_u8)]
fn test_z2_mapper() {
    let mut mapper = ZCharacterMapperV2::create();
    // 0 is always a space
    assert_eq!(b' ', mapper.map(0));

    // 1 is abbreviation
    assert_eq!(ABBREV_1, mapper.map(1));

    // Test shifts. 8 will normally be a c. Shifted
    // up, will return C. Shifted down, will return 0.
    // Shift should only be for a single character
    assert_eq!(b'c', mapper.map(8));
    assert_eq!(NOPRINT_CHAR, mapper.map(2));
    assert_eq!(b'C', mapper.map(8));
    assert_eq!(b'c', mapper.map(8));

    // Shift down (3) will work the other way
    assert_eq!(b'c', mapper.map(8));
    assert_eq!(NOPRINT_CHAR, mapper.map(3));
    assert_eq!(b'0', mapper.map(8));
    assert_eq!(b'c', mapper.map(8));

    // Test shift lock. These switch alphabets for all subsequent chars
    assert_eq!(b'c', mapper.map(8));
    assert_eq!(NOPRINT_CHAR, mapper.map(4));
    assert_eq!(b'C', mapper.map(8));
    assert_eq!(b'C', mapper.map(8));
    assert_eq!(NOPRINT_CHAR, mapper.map(5));
    assert_eq!(b'c', mapper.map(8));
    assert_eq!(NOPRINT_CHAR, mapper.map(5));
    assert_eq!(b'0', mapper.map(8));
    assert_eq!(b'0', mapper.map(8));
    assert_eq!(NOPRINT_CHAR, mapper.map(4));

    // 6 will return a, A, or the special "wait for 10 bit char"
    // based on alphabet
    assert_eq!(b'a', mapper.map(6));
    assert_eq!(NOPRINT_CHAR, mapper.map(2));
    assert_eq!(b'A', mapper.map(6));
    assert_eq!(NOPRINT_CHAR, mapper.map(3));
    assert_eq!(TOGGLE_EXTENDED, mapper.map(6));

    // 7 is a newline in alphabet 2
    assert_eq!(NOPRINT_CHAR, mapper.map(5));
    assert_eq!(b'\n', mapper.map(7));
}

#[test]
fn test_z3_mapper() {
    let mut mapper = ZCharacterMapperV3::create();
    // 0 is always a space
    assert_eq!(b' ', mapper.map(0));

    // 1,2,3 are abbreviations
    assert_eq!(ABBREV_1, mapper.map(1));
    assert_eq!(ABBREV_2, mapper.map(2));
    assert_eq!(ABBREV_3, mapper.map(3));

    // Test shifts. 8 will normally be a c. Shifted
    // up, will return C. Shifted down, will return 0.
    // Shift should only be for a single character
    assert_eq!(b'c', mapper.map(8));
    assert_eq!(NOPRINT_CHAR, mapper.map(4));
    assert_eq!(b'C', mapper.map(8));
    assert_eq!(b'c', mapper.map(8));

    // Shift down (5) will work the other way
    assert_eq!(b'c', mapper.map(8));
    assert_eq!(NOPRINT_CHAR, mapper.map(5));
    assert_eq!(b'0', mapper.map(8));
    assert_eq!(b'c', mapper.map(8));

    // 6 will return a, A, or the special "wait for 10 bit char"
    // based on alphabet
    assert_eq!(b'a', mapper.map(6));
    assert_eq!(NOPRINT_CHAR, mapper.map(4));
    assert_eq!(b'A', mapper.map(6));
    assert_eq!(NOPRINT_CHAR, mapper.map(5));
    assert_eq!(TOGGLE_EXTENDED, mapper.map(6));

    // 7 is a newline in alphabet 2
    assert_eq!(NOPRINT_CHAR, mapper.map(5));
    assert_eq!(b'\n', mapper.map(7));
}

#[test]
fn test_jump_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_ne!(vm.get_pc(), 0x1234);
    vm.handle_action(Action::Jump(0x1234), &mut io);
    assert_eq!(vm.get_pc(), 0x1234);

    Ok(())
}

#[test]
fn test_print_address_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_ne!(vm.get_pc(), 0x1234);
    vm.handle_action(
        // 1612 is just address of a string in the basic2 story
        Action::PrintAddress(1612, 0x1234, false, false),
        &mut io,
    );

    assert_eq!("Hello world\n", io.get_text_buffer());

    assert_eq!(vm.get_pc(), 0x1234);

    Ok(())
}

#[test]
fn test_print_string_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_ne!(vm.get_pc(), 0x1234);
    vm.handle_action(
        Action::PrintString(String::from("A String"), 0x1234),
        &mut io,
    );

    assert_eq!("A String", io.get_text_buffer());

    assert_eq!(vm.get_pc(), 0x1234);

    Ok(())
}

#[test]
fn test_print_char_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_ne!(vm.get_pc(), 0x1234);
    vm.handle_action(Action::PrintChar(66, 0x1234), &mut io);

    assert_eq!("B", io.get_text_buffer());

    assert_eq!(vm.get_pc(), 0x1234);

    Ok(())
}

#[test]
fn test_read_line_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");
    assert!(!io.waiting_for_input());

    let old_pc = vm.get_pc();
    vm.handle_action(Action::ReadLine(1, 0x2234, 0x3234, 0x1234), &mut io);
    assert_eq!(vm.get_pc(), old_pc);
    assert!(io.waiting_for_input());

    match vm.get_state() {
        VMState::WaitingForInput(pc_addr, text_addr, parse_addr) => {
            assert_eq!(0x1234, pc_addr);
            assert_eq!(0x2234, text_addr);
            assert_eq!(0x3234, parse_addr);
        }
        _ => {
            panic!();
        }
    }

    Ok(())
}

#[test]
fn test_pop_and_store_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    // Push two items on stack.
    vm.set_variable(0, 1)?;
    vm.set_variable(0, 2)?;

    assert_eq!(2, vm.peek_variable(0, false)?);
    assert_eq!(0, vm.peek_variable(100, false)?);
    assert_ne!(vm.get_pc(), 0x1234);
    vm.handle_action(Action::PopAndStore(100, 0x1234), &mut io);
    assert_eq!(vm.get_pc(), 0x1234);
    assert_eq!(1, vm.peek_variable(0, false)?);
    assert_eq!(2, vm.peek_variable(100, false)?);

    Ok(())
}

#[test]
fn test_pop_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    // Push two items on stack.
    vm.set_variable(0, 1)?;
    vm.set_variable(0, 2)?;

    assert_eq!(2, vm.peek_variable(0, false)?);
    assert_ne!(vm.get_pc(), 0x1234);
    vm.handle_action(Action::Pop(0x1234), &mut io);
    assert_eq!(vm.get_pc(), 0x1234);
    assert_eq!(1, vm.peek_variable(0, false)?);

    Ok(())
}

#[test]
fn test_nop_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_ne!(vm.get_pc(), 0x1234);
    vm.handle_action(Action::Nop(0x1234), &mut io);
    assert_eq!(vm.get_pc(), 0x1234);

    Ok(())
}
#[test]
fn test_show_status_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();

    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_eq!(VMState::Running, vm.get_state());
    assert_eq!("", io.status_left);
    assert_eq!("", io.status_right);

    vm.handle_action(Action::ShowStatus(0x1234), &mut io);
    assert_eq!(VMState::Running, vm.get_state());
    assert_eq!(0x1234, vm.get_pc());
    assert_eq!(VMState::Running, vm.get_state());

    assert_eq!("Nothing", io.status_left);
    assert_eq!("0/0", io.status_right);

    Ok(())
}

#[test]
fn test_split_window_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();

    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_eq!(VMState::Running, vm.get_state());
    assert_eq!(0, io.upper_window_lines);

    vm.handle_action(Action::SplitWindow(2, 0x1234), &mut io);
    assert_eq!(2, io.upper_window_lines);
    assert_eq!(0x1234, vm.get_pc());

    Ok(())
}

#[test]
fn test_set_window_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();

    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_eq!(VMState::Running, vm.get_state());
    assert_eq!(WindowLayout::Lower, io.window);

    vm.handle_action(Action::SetWindow(WindowLayout::Upper, 0x1234), &mut io);
    assert_eq!(VMState::Running, vm.get_state());
    assert_eq!(WindowLayout::Upper, io.window);
    assert_eq!(0x1234, vm.get_pc());

    Ok(())
}

#[test]
fn test_save_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();

    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    let old_pc = vm.get_pc();
    assert_eq!(VMState::Running, vm.get_state());

    vm.handle_action(Action::Save(0x1234, false, 0x4321), &mut io);
    assert_eq!(VMState::SavePrompt(0x4321, 0x1234), vm.get_state());
    assert_eq!(old_pc + 1, vm.get_pc());

    let old_pc = vm.get_pc();
    vm.handle_action(Action::Save(0x1234, true, 0x4321), &mut io);
    assert_eq!(VMState::SavePrompt(0x1235, 0x4321), vm.get_state());
    assert_eq!(old_pc + 1, vm.get_pc());

    Ok(())
}

#[test]
fn test_restore_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();

    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_eq!(VMState::Running, vm.get_state());

    vm.handle_action(Action::Restore(0x1234, false, 0x4321), &mut io);
    assert_eq!(VMState::RestorePrompt, vm.get_state());
    assert_eq!(0x1234, vm.get_pc());

    vm.handle_action(Action::Restore(0x1234, true, 0x4321), &mut io);
    assert_eq!(VMState::RestorePrompt, vm.get_state());
    assert_eq!(0x4321, vm.get_pc());

    Ok(())
}

#[test]
fn test_restart_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();

    // Test correct flags get reset or not based on spec
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_eq!(VMState::Running, vm.get_state());
    assert!(!vm.get_bit(0x1, 4)?); // status unavailable
    assert!(vm.get_bit(0x1, 5)?); // io split available
    assert!(!vm.get_bit(0x1, 6)?); // variable pitch font

    assert!(!vm.get_bit(0x10, 0)?); // transcript, preserved
    assert!(!vm.get_bit(0x10, 1)?); // fixed pitch, preserved

    assert_eq!(1603, vm.get_pc());

    vm.set_bit(0x01, 4, true)?;
    vm.set_bit(0x01, 5, false)?;
    vm.set_bit(0x01, 6, true)?;
    vm.set_bit(0x10, 0, true)?;
    vm.set_bit(0x10, 1, true)?;
    vm.set_pc(0x1234);
    vm.handle_action(Action::Restart(), &mut io);

    assert!(!vm.get_bit(0x1, 4)?); // status unavailable
    assert!(vm.get_bit(0x1, 5)?); // io split available
    assert!(!vm.get_bit(0x1, 6)?); // variable pitch font

    assert!(vm.get_bit(0x10, 0)?); // transcript, preserved
    assert!(vm.get_bit(0x10, 1)?); // fixed pitch, preserved

    assert_eq!(1603, vm.get_pc());
    assert_eq!(VMState::Running, vm.get_state());

    Ok(())
}

#[test]
fn test_sound_effect_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_eq!(0, io.sound_number);
    assert_eq!(0, io.sound_effect);
    assert_eq!(0, io.sound_volume);
    assert_eq!(1603, vm.get_pc());

    vm.handle_action(Action::SoundEffect(0x01, 0x02, 0x03, 0x1234), &mut io);
    assert_eq!(1, io.sound_number);
    assert_eq!(2, io.sound_effect);
    assert_eq!(3, io.sound_volume);
    assert_eq!(0x1234, vm.get_pc());
    Ok(())
}

#[test]
fn test_switch_input_stream_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_eq!(io.input_stream, InputStreamEnum::Keyboard);

    vm.handle_action(
        Action::SwitchInputStream(InputStreamEnum::Keyboard, 0x1234),
        &mut io,
    );
    assert_eq!(io.input_stream, InputStreamEnum::Keyboard);
    assert_eq!(0x1234, vm.get_pc());

    vm.handle_action(
        Action::SwitchInputStream(InputStreamEnum::File, 0x1236),
        &mut io,
    );
    assert_eq!(io.input_stream, InputStreamEnum::File);
    assert_eq!(0x1236, vm.get_pc());

    Ok(())
}

#[test]
fn test_toggle_output_stream_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert!(!io.is_transcript_active());
    assert!(io.is_screen_output_active());
    assert!(!io.is_command_output_active());
    assert_eq!(VMState::Running, vm.get_state());

    vm.handle_action(
        Action::SetOutputStream(OutputStreamEnum::Transcript, None, true, 0x1234),
        &mut io,
    );

    // Note transcript is not immediately set, instead moves to transcript prompt state
    assert_eq!(VMState::TranscriptPrompt, vm.get_state());
    assert!(!io.is_transcript_active());
    assert!(io.is_screen_output_active());
    assert!(!io.is_command_output_active());
    assert_eq!(0x1234, vm.get_pc());

    vm.handle_action(
        Action::SetOutputStream(OutputStreamEnum::Commands, None, true, 0x1236),
        &mut io,
    );

    assert!(!io.is_transcript_active());
    assert!(io.is_screen_output_active());
    assert!(!io.is_command_output_active());
    assert_eq!(0x1236, vm.get_pc());
    // Note command prompt is not immediately set, instead moves to command prompt state
    assert_eq!(VMState::CommandOutputPrompt, vm.get_state());
    vm.handle_action(
        Action::SetOutputStream(OutputStreamEnum::Screen, None, false, 0x1238),
        &mut io,
    );

    assert!(!io.is_transcript_active());
    assert!(!io.is_screen_output_active());
    assert!(!io.is_command_output_active());
    assert_eq!(0x1238, vm.get_pc());
    assert_eq!(VMState::CommandOutputPrompt, vm.get_state());

    // Activate other streams to validate they aren't written to
    vm.set_state(VMState::Running);
    io.set_transcript(true);
    io.set_screen_output(true);
    io.set_command_output(true);
    io.panic_on_output = true;

    // Memory state should write to memory locations specified. First word should contain
    // number of bytes, then bytes thereafter. Should not print to any other stream.
    vm.handle_action(
        Action::SetOutputStream(OutputStreamEnum::Memory, Some(0x0410), true, 0x1238),
        &mut io,
    );
    assert_eq!(0x1238, vm.get_pc());
    assert_eq!(VMState::Running, vm.get_state());

    vm.handle_action(Action::PrintChar(65, 0x1238), &mut io);
    // Check that setting output stream works as a stack
    vm.handle_action(
        Action::SetOutputStream(OutputStreamEnum::Memory, Some(0x0420), true, 0x1240),
        &mut io,
    );
    assert_eq!(0x1240, vm.get_pc());

    vm.handle_action(Action::PrintChar(66, 0x1238), &mut io);
    vm.handle_action(Action::PrintChar(67, 0x1238), &mut io);
    vm.handle_action(Action::PrintChar(10, 0x1238), &mut io);

    vm.handle_action(
        Action::SetOutputStream(OutputStreamEnum::Memory, None, false, 0x1242),
        &mut io,
    );

    assert_eq!(0x1242, vm.get_pc());
    vm.handle_action(Action::PrintChar(68, 0x1238), &mut io);

    vm.handle_action(
        Action::SetOutputStream(OutputStreamEnum::Memory, None, false, 0x1244),
        &mut io,
    );

    assert_eq!(0x1244, vm.get_pc());

    // Output should no longer panic or write to memory
    io.panic_on_output = false;
    vm.handle_action(Action::PrintChar(69, 0x1238), &mut io);

    assert_eq!(VMState::Running, vm.get_state());
    // Final memory should be AD for first, BC\r for second
    // Second is to validate 2.1.2.2.1 which disallows printing \n
    assert_eq!(2, vm.get_word(0x0410)?);
    assert_eq!(65, vm.get_byte(0x0412)?); // A
    assert_eq!(68, vm.get_byte(0x0413)?); // D
    assert_eq!(3, vm.get_word(0x0420)?);
    assert_eq!(66, vm.get_byte(0x0422)?); // B
    assert_eq!(67, vm.get_byte(0x0423)?); // C
    assert_eq!(13, vm.get_byte(0x0424)?); // \r

    // Check failure after 17 pushes"

    for _ in 0..16 {
        vm.handle_action(
            Action::SetOutputStream(OutputStreamEnum::Memory, Some(0x0420), true, 0x1240),
            &mut io,
        );
        assert_eq!(VMState::Running, vm.get_state());
    }

    vm.handle_action(
        Action::SetOutputStream(OutputStreamEnum::Memory, Some(0x0420), true, 0x1240),
        &mut io,
    );
    assert_eq!(VMState::Error, vm.get_state());

    Ok(())
}

#[test]
fn test_setattr() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert!(!vm.get_attribute(OBJECT_TEST_PARENT, 1)?);
    assert!(!vm.get_attribute(OBJECT_TEST_PARENT, 2)?);
    assert!(!vm.get_attribute(OBJECT_CLASS, 2)?);

    vm.handle_action(
        Action::SetAttr(OBJECT_TEST_PARENT as u16, 2, true, 0x100),
        &mut io,
    );
    assert_eq!(0x100, vm.get_pc());

    assert!(!vm.get_attribute(OBJECT_TEST_PARENT, 1)?);
    assert!(vm.get_attribute(OBJECT_TEST_PARENT, 2)?);
    assert!(!vm.get_attribute(OBJECT_CLASS, 2)?);

    vm.handle_action(
        Action::SetAttr(OBJECT_TEST_PARENT as u16, 2, false, 0x100),
        &mut io,
    );

    assert!(!vm.get_attribute(OBJECT_TEST_PARENT, 1)?);
    assert!(!vm.get_attribute(OBJECT_TEST_PARENT, 2)?);
    assert!(!vm.get_attribute(OBJECT_CLASS, 2)?);

    Ok(())
}

#[test]
fn test_quit_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_eq!(VMState::Running, vm.get_state());
    vm.handle_action(Action::Quit(), &mut io);
    assert_eq!(VMState::Quit, vm.get_state());

    Ok(())
}

#[test]
fn test_setproperty_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_eq!(VMState::Running, vm.get_state());
    assert_ne!(0x100, vm.get_pc());
    assert_eq!(1077, vm.get_property(OBJECT_TEST_CHILD, 3)?.value);
    vm.handle_action(
        Action::SetProperty(OBJECT_TEST_CHILD as u16, 3, 0xcc, 0x100),
        &mut io,
    );
    assert_eq!(VMState::Running, vm.get_state());
    assert_eq!(0x100, vm.get_pc());
    assert_eq!(0xcc, vm.get_property(OBJECT_TEST_CHILD, 3)?.value);

    Ok(())
}

#[test]
fn test_insertobject_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_eq!(VMState::Running, vm.get_state());
    assert_ne!(0x100, vm.get_pc());
    assert_eq!(OBJECT_TEST_PARENT, vm.get_parent(OBJECT_TEST_CHILD)?);
    vm.handle_action(
        Action::InsertObject(OBJECT_TEST_CHILD as u16, OBJECT_TEST_TEXT as u16, 0x100),
        &mut io,
    );
    assert_eq!(VMState::Running, vm.get_state());
    assert_eq!(0x100, vm.get_pc());
    assert_eq!(OBJECT_TEST_TEXT, vm.get_parent(OBJECT_TEST_CHILD)?);

    Ok(())
}

#[test]
fn test_removeobject_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_eq!(VMState::Running, vm.get_state());
    assert_ne!(0x100, vm.get_pc());
    assert_eq!(OBJECT_TEST_PARENT, vm.get_parent(OBJECT_TEST_CHILD)?);
    vm.handle_action(
        Action::RemoveObject(OBJECT_TEST_CHILD as u16, 0x100),
        &mut io,
    );
    assert_eq!(VMState::Running, vm.get_state());
    assert_eq!(0x100, vm.get_pc());
    assert_eq!(OBJECT_NOTHING, vm.get_parent(OBJECT_TEST_CHILD)?);

    Ok(())
}

#[test]
fn test_storebyte_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_ne!(0x0300, vm.get_pc());
    assert_ne!(0x32, vm.get_byte(0x0123)?);
    vm.handle_action(Action::StoreByte(0x0123, 0x32, 0x0300), &mut io);
    assert_eq!(0x32, vm.get_byte(0x0123)?);
    assert_eq!(0x0300, vm.get_pc());

    // test out of bounds write
    vm.handle_action(Action::StoreByte(0x01, 0x32, 0x0300), &mut io);
    assert_eq!(VMState::Error, vm.get_state()); // header

    vm.set_state(VMState::Running);
    vm.handle_action(Action::StoreByte(0x0623, 0x32, 0x0300), &mut io); // static mem
    assert_eq!(VMState::Error, vm.get_state());

    Ok(())
}

#[test]
fn test_storebytes_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_ne!(0x0300, vm.get_pc());
    assert_ne!(0x32, vm.get_byte(0x0123)?);
    vm.handle_action(
        Action::StoreBytes(0x0123, vec![0x32, 0x33, 0x34], 0x0300),
        &mut io,
    );
    assert_eq!(0x32, vm.get_byte(0x0123)?);
    assert_eq!(0x33, vm.get_byte(0x0124)?);
    assert_eq!(0x34, vm.get_byte(0x0125)?);
    assert_eq!(0x0300, vm.get_pc());

    // test out of bounds write
    vm.handle_action(
        Action::StoreBytes(0x01, vec![0x32, 0x33, 0x34], 0x0300),
        &mut io,
    );
    assert_eq!(VMState::Error, vm.get_state()); // header
    vm.set_state(VMState::Running);
    vm.handle_action(
        Action::StoreBytes(0x18, vec![0x32, 0x33, 0x34], 0x0300),
        &mut io,
    );
    assert_eq!(VMState::Error, vm.get_state()); // header

    vm.set_state(VMState::Running);
    vm.handle_action(Action::StoreBytes(0x0623, vec![0x32], 0x0300), &mut io); // static mem
    assert_eq!(VMState::Error, vm.get_state());

    Ok(())
}

#[test]
fn test_storevariable_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_ne!(0x0300, vm.get_pc());
    assert_ne!(0x4321, vm.get_variable(0xfc)?);
    vm.handle_action(Action::StoreVariable(0xfc, 0x4321, 0x0300, false), &mut io);
    assert_eq!(0x4321, vm.get_variable(0xfc)?);
    assert_eq!(0x0300, vm.get_pc());

    // Test stack behavior
    vm.set_variable(0, 0xff)?;
    vm.handle_action(Action::StoreVariable(0, 0xcc, 0x0300, false), &mut io);
    assert_eq!(0xcc, vm.get_variable(0)?);
    assert_eq!(0xff, vm.get_variable(0)?);

    vm.set_variable(0, 0xff)?;
    vm.handle_action(Action::StoreVariable(0, 0xcc, 0x0300, true), &mut io);
    assert_eq!(0xcc, vm.get_variable(0)?);
    assert_eq!(
        Err(ZmachineError::MemoryStackOverflowRoutine()),
        vm.get_variable(0)
    ); // Replaced on stack, so no more items

    Ok(())
}

#[test]
fn test_input_stream_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");
    assert_eq!(InputStreamEnum::Keyboard, io.input_stream);
    assert_ne!(0x0300, vm.get_pc());
    vm.handle_action(
        Action::SwitchInputStream(InputStreamEnum::File, 0x0300),
        &mut io,
    );
    assert_eq!(0x0300, vm.get_pc());
    assert_eq!(InputStreamEnum::File, io.input_stream);

    vm.handle_action(
        Action::SwitchInputStream(InputStreamEnum::Keyboard, 0x0300),
        &mut io,
    );
    assert_eq!(InputStreamEnum::Keyboard, io.input_stream);

    Ok(())
}

#[test]
fn test_randomandstore_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");
    vm.reseed_rng_predicable(2);
    assert_eq!(0, vm.get_variable(0xff)?);
    assert_ne!(0x0300, vm.get_pc());

    vm.handle_action(Action::RandomAndStore(100, 0xff, 0x0300), &mut io);
    assert_eq!(1, vm.get_variable(0xff)?);
    assert_eq!(0x0300, vm.get_pc());

    vm.handle_action(Action::RandomAndStore(100, 0xff, 0x0400), &mut io);
    assert_eq!(2, vm.get_variable(0xff)?);
    assert_eq!(0x0400, vm.get_pc());

    Ok(())
}

#[test]
fn test_reseedrngandstore_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");
    vm.set_variable(0xff, 0xff)?;
    assert_ne!(0x0300, vm.get_pc());

    vm.handle_action(Action::ReseedRNGAndStore(0, 0xff, 0x0300), &mut io);
    assert_eq!(0, vm.get_variable(0xff)?);
    assert_eq!(0x0300, vm.get_pc());

    Ok(())
}

#[test]
fn test_storevariableandreturn_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_eq!(0, vm.get_variable(0xff)?);

    // Magic number is location of existing call routine
    vm.handle_action(Action::Call(0x040f, 0, 0, 0, 0, 0xff, 0), &mut io);

    assert_eq!(0, vm.get_variable(0xff)?);
    assert_eq!(0, vm.get_variable(0xcc)?);
    vm.handle_action(Action::StoreVariableAndReturn(0xcc, 0xdd, 111), &mut io);
    assert_eq!(111, vm.get_variable(0xff)?);
    assert_eq!(0xdd, vm.get_variable(0xcc)?);

    Ok(())
}

#[test]
fn test_storeword_action() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_ne!(0x0300, vm.get_pc());
    assert_ne!(0x4321, vm.get_word(0x0123)?);
    vm.handle_action(Action::StoreWord(0x0123, 0x4321, 0x0300), &mut io);
    assert_eq!(0x4321, vm.get_word(0x0123)?);
    assert_eq!(0x0300, vm.get_pc());

    // test out of bounds write
    vm.handle_action(Action::StoreWord(0x01, 0x32, 0x0300), &mut io);
    assert_eq!(VMState::Error, vm.get_state()); // header

    vm.set_state(VMState::Running);
    vm.handle_action(Action::StoreWord(0x0623, 0x32, 0x0300), &mut io); // static mem
    assert_eq!(VMState::Error, vm.get_state());

    Ok(())
}

#[test]
fn test_call_and_return() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    assert_eq!(0, vm.get_variable(0xff)?);

    // Magic number is location of existing call routine
    vm.handle_action(Action::Call(0x040f, 0, 0, 0, 0, 0xff, 0), &mut io);

    assert_eq!(0, vm.get_variable(0xff)?);
    vm.handle_action(Action::Return(111), &mut io);
    assert_eq!(111, vm.get_variable(0xff)?);

    Ok(())
}

#[test]
// Test 6.4.3 -- call empty routine is legal
fn test_call_empty() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    vm.set_variable(100, 200)?;
    vm.handle_action(Action::Call(0, 0, 0, 0, 0, 100, 0), &mut io);

    assert_eq!(0, vm.get_variable(100)?);

    Ok(())
}

#[test]
#[should_panic]
fn test_return_from_main() {
    let mut io = DebugIO::create();
    match VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false) {
        Ok(mut vm) => {
            // Return from main will panic
            vm.handle_action(Action::Return(111), &mut io);
        }
        Err(_) => {
            assert_eq!(0, 1, "Error creating vm");
        }
    }
}
#[test]
fn test_rng() -> Result<(), ZmachineError> {
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    // See remarks at end of section 2.4
    // RNG can be put in a predictable mode for testing
    vm.reseed_rng_predicable(1);
    assert_eq!(1, vm.random_int(1));
    assert_eq!(1, vm.random_int(2));
    assert_eq!(1, vm.random_int(3));

    vm.reseed_rng_predicable(3);
    assert_eq!(1, vm.random_int(3));
    assert_eq!(2, vm.random_int(3));
    assert_eq!(3, vm.random_int(3));
    assert_eq!(1, vm.random_int(3));
    assert_eq!(1, vm.random_int(1));
    assert_eq!(1, vm.random_int(1));

    // Test range
    vm.reseed_rng();
    assert_eq!(1, vm.random_int(1));
    assert_eq!(1, vm.random_int(1));

    Ok(())
}

#[test]
fn test_save_and_restore_basic_1() -> Result<(), ZmachineError> {
    // Load a game
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic), false, false)
        .expect("Error loading story");

    // Test and preserve header bits
    assert_eq!(VMState::Running, vm.get_state());
    assert!(!vm.get_bit(0x1, 4)?); // status unavailable
    assert!(vm.get_bit(0x1, 5)?); // io split available
    assert!(!vm.get_bit(0x1, 6)?); // variable pitch font
    assert!(!vm.get_bit(0x10, 0)?); // transcript, preserved
    assert!(!vm.get_bit(0x10, 1)?); // fixed pitch, preserved

    // Set a local Var, a global Var, and push to stack, and set PC
    vm.set_variable(0, 0xfeec)?;
    vm.force_set_local(1, 0xfeed);
    vm.set_variable(255, 0xfeee)?;
    vm.set_pc(0x1234);

    // Run a save
    let data = vm.get_quetzal_data(false);

    // Reload a fresh vm, then restore
    let mut vm2 = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic), false, false)
        .expect("Error loading story");

    vm2.set_bit(0x01, 4, true)?;
    vm2.set_bit(0x01, 5, false)?;
    vm2.set_bit(0x01, 6, true)?;
    vm2.set_bit(0x10, 0, true)?;
    vm2.set_bit(0x10, 1, true)?;
    vm2.restore_game(data)?;

    // Check that vars are preserved
    assert_eq!(0xfeec, vm2.peek_variable(0, false)?);
    assert_eq!(0xfeed, vm2.get_variable(1)?);
    assert_eq!(0xfeee, vm2.get_variable(255)?);

    // Check that flags are correctly preserved
    assert!(!vm2.get_bit(0x1, 4)?); // status unavailable
    assert!(vm2.get_bit(0x1, 5)?); // io split available
    assert!(!vm2.get_bit(0x1, 6)?); // variable pitch font

    assert!(vm2.get_bit(0x10, 0)?); // transcript, preserved
    assert!(vm2.get_bit(0x10, 1)?); // fixed pitch, preserved

    // Check PC
    assert_eq!(0x1235, vm2.get_pc()); // PC is one byte ahead after a restore
                                      // Expand to test all stack frames, local variables, global variables

    // Decrement PC and adjust header RST fields so states will match
    vm2.set_pc(0x1234);
    vm2.set_bit(0x10, 0, false)?;
    vm2.set_bit(0x10, 1, false)?;
    assert_eq!(vm.get_state_string(), vm2.get_state_string());
    Ok(())
}

#[test]
fn test_save_and_restore_basic_3() -> Result<(), ZmachineError> {
    // Load a game
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic3), false, false)
        .expect("Error loading story");

    // "Play" it until waiting for line is hit
    let mut counter = 0;
    while counter < 10000 && vm.get_state() == VMState::Running {
        vm.tick(&mut io);
        counter += 1;
    }

    assert_eq!(VMState::WaitingForInput(1356, 1168, 1231), vm.get_state());

    // Set a local Var, a global Var, and push to stack, and set PC
    vm.set_variable(0, 0xfeec)?;
    vm.force_set_local(1, 0xfeed);
    vm.set_variable(255, 0xfeee)?;
    vm.set_pc(0x1234);

    // Run a save
    let data = vm.get_quetzal_data(false);

    // Reload a fresh vm, then restore
    let mut vm2 =
        VM::create_from_story_bytes(load_test_story_data(TestStory::Basic3), false, false)
            .expect("Error loading story");

    vm2.restore_game(data)?;

    // Check that vars are preserved
    assert_eq!(0xfeec, vm2.peek_variable(0, false)?);
    assert_eq!(0xfeed, vm2.get_variable(1)?);
    assert_eq!(0xfeee, vm2.get_variable(255)?);

    // Check PC

    assert_eq!(0x1235, vm2.get_pc()); // PC is one byte ahead after a restore
                                      // Expand to test all stack frames, local variables, global variables

    // Decrement PC and adjust header RST fields so states will match
    vm2.set_pc(0x1234);
    vm2.set_bit(0x10, 0, false)?;
    vm2.set_bit(0x10, 1, false)?;
    vm2.set_state(VMState::WaitingForInput(1356, 1168, 1231));
    assert_eq!(vm.get_state_string(), vm2.get_state_string());

    Ok(())
}

fn generate_random_byte_vec(len: u16) -> Vec<u8> {
    let mut v = vec![];
    let mut rng = rand::thread_rng();
    for _ in 0..len {
        let byte: u8 = rng.gen();
        v.push(byte);
    }
    v
}

#[test]
fn test_save_and_restore_compressed() -> Result<(), ZmachineError> {
    // Test that a compressed save/restore works correctly
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic3), false, false)
        .expect("Error loading story");

    // "Play" it until waiting for line is hit
    let mut counter = 0;
    while counter < 10000 && vm.get_state() == VMState::Running {
        vm.tick(&mut io);
        counter += 1;
    }

    assert_eq!(VMState::WaitingForInput(1356, 1168, 1231), vm.get_state());

    // Set a local Var, a global Var, and push to stack, and set PC
    vm.set_variable(0, 0xfeec)?;
    vm.force_set_local(1, 0xfeed);
    vm.set_variable(255, 0xfeee)?;
    vm.set_pc(0x1234);

    // Run a compressed save
    let data = vm.get_quetzal_data(true);
    let mut data_copy = data.clone();

    // Reload a fresh vm, then restore
    let mut vm2 =
        VM::create_from_story_bytes(load_test_story_data(TestStory::Basic3), false, false)
            .expect("Error loading story");

    vm2.restore_game(data)?;

    // Check that vars are preserved
    assert_eq!(0xfeec, vm2.peek_variable(0, false)?);
    assert_eq!(0xfeed, vm2.get_variable(1)?);
    assert_eq!(0xfeee, vm2.get_variable(255)?);

    // Check PC

    assert_eq!(0x1235, vm2.get_pc()); // PC is one byte ahead after a restore
                                      // Expand to test all stack frames, local variables, global variables

    // Decrement PC and adjust header RST fields so states will match
    vm2.set_pc(0x1234);
    vm2.set_bit(0x10, 0, false)?;
    vm2.set_bit(0x10, 1, false)?;
    vm2.set_state(VMState::WaitingForInput(1356, 1168, 1231));
    assert_eq!(vm.get_state_string(), vm2.get_state_string());

    // Test overflow error
    data_copy.data = generate_random_byte_vec(0xffff);
    data_copy.data_is_compressed = true;
    match vm2.restore_game(data_copy) {
        Ok(_) => panic!("Expected error"),
        Err(msg) => assert_eq!(msg, ZmachineError::SaveDataOverflowError()),
    }

    Ok(())
}

fn compress_and_decompress(story: Vec<u8>, original_memory: Vec<u8>) {
    let mut memory = original_memory.clone();
    let compressed = compress_story_data(0, &story, &memory);
    load_compressed_save_data(&compressed, 0, &story, &mut memory).expect("Error decompressing");

    assert_eq!(memory, original_memory);
}

#[test]
fn test_compressed_save() -> Result<(), ZmachineError> {
    compress_and_decompress(vec![], vec![]);
    compress_and_decompress(vec![1], vec![1]);
    compress_and_decompress(vec![1, 2, 3], vec![3, 2, 1]);
    compress_and_decompress(vec![0, 0, 0, 0, 0], vec![1, 2, 3, 4, 5]);
    compress_and_decompress(vec![1, 2, 3, 4, 5], vec![0, 0, 0, 0, 0]);

    let mut rng = rand::thread_rng();
    for _ in 0..100 {
        let len: u16 = rng.gen();

        compress_and_decompress(generate_random_byte_vec(len), generate_random_byte_vec(len));
    }

    Ok(())
}
#[test]
fn test_parse_input_text() -> Result<(), ZmachineError> {
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic3), false, false)
        .expect("Error loading story");

    // test multiple words with two in dict-- "some text ok"
    vm.set_bytes(
        0x100,
        vec![
            0x73, 0x6f, 0x6d, 0x65, 0x20, 0x74, 0x65, 0x78, 0x74, 0x20, 0x6f, 0x6b, 0x00,
        ],
    )?;

    // Max 10 words
    vm.set_byte(0x200, 0x0a)?;

    vm.parse_input_text(0xff, 0x200)?; // Call with text buffer one byte before first byte as byte 0 is ignored

    assert_eq!(0x03, vm.get_byte(0x201)?); // first byte has word count

    // Will have three blocks of 4 bytes containing: address, letter count, offset into buffer (0th byte is size)
    let mut addr = 0x202;
    assert_eq!(1289, vm.get_word(addr)?);
    addr += WORD_LENGTH;
    assert_eq!(0x04, vm.get_byte(addr)?);
    addr += BYTE_LENGTH;
    assert_eq!(0x01, vm.get_byte(addr)?);
    addr += BYTE_LENGTH;

    assert_eq!(1296, vm.get_word(addr)?);
    addr += WORD_LENGTH;
    assert_eq!(0x04, vm.get_byte(addr)?);
    addr += BYTE_LENGTH;
    assert_eq!(0x06, vm.get_byte(addr)?);
    addr += BYTE_LENGTH;

    assert_eq!(0x0000, vm.get_word(addr)?);
    addr += WORD_LENGTH;
    assert_eq!(0x02, vm.get_byte(addr)?);
    addr += BYTE_LENGTH;
    assert_eq!(0x0b, vm.get_byte(addr)?);

    // Text max word count
    // Max 1 words
    vm.set_byte(0x200, 0x01)?;
    vm.parse_input_text(0xff, 0x200)?; // Call with text buffer one byte before first byte as byte 0 is ignored
    assert_eq!(0x01, vm.get_byte(0x201)?); // first byte has word count

    // test empty
    vm.set_byte(0x100, 0x00)?;
    vm.parse_input_text(0xff, 0x200)?; // Call with text buffer one byte before first byte as byte 0 is ignored
    assert_eq!(0x00, vm.get_byte(0x201)?); // first byte has word count

    Ok(())
}

#[test]
#[allow(clippy::cognitive_complexity)]
#[allow(clippy::char_lit_as_u8)]
fn test_split_text() -> Result<(), ZmachineError> {
    let mut vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic3), false, false)
        .expect("Error loading story");

    // Dictionary has some, more and text as words
    // Searators are .,"
    // Set a fake empty string for testing
    vm.set_byte(0x100, 0)?;
    let v = vm.split_text(0x100)?;
    assert_eq!(0, v.len());

    // Single word "some"
    vm.set_byte(0x100, 0x73)?;
    vm.set_byte(0x101, 0x6f)?;
    vm.set_byte(0x102, 0x6d)?;
    vm.set_byte(0x103, 0x65)?;
    vm.set_byte(0x104, 0x00)?;

    let v = vm.split_text(0x100)?;
    assert_eq!(1, v.len());
    assert_eq!(vec![115, 111, 109, 101], v[0].word);
    assert_eq!(0, v[0].index);

    // test multiple words -- "some text"
    vm.set_byte(0x100, 0x73)?;
    vm.set_byte(0x101, 0x6f)?;
    vm.set_byte(0x102, 0x6d)?;
    vm.set_byte(0x103, 0x65)?;
    vm.set_byte(0x104, 0x20)?;
    vm.set_byte(0x105, 0x74)?;
    vm.set_byte(0x106, 0x65)?;
    vm.set_byte(0x107, 0x78)?;
    vm.set_byte(0x108, 0x74)?;
    vm.set_byte(0x109, 0x00)?;

    let v = vm.split_text(0x100)?;
    assert_eq!(2, v.len());
    assert_eq!(vec![115, 111, 109, 101], v[0].word);
    assert_eq!(0, v[0].index);
    assert_eq!(vec![0x74, 0x65, 0x78, 0x74], v[1].word);
    assert_eq!(5, v[1].index);

    // Spaces don't count as words but separators do.
    vm.set_byte(0x104, 0x22)?; // "
    let v = vm.split_text(0x100)?;
    assert_eq!(3, v.len());
    assert_eq!(vec![115, 111, 109, 101], v[0].word);
    assert_eq!(0, v[0].index);
    assert_eq!(vec![0x22], v[1].word);
    assert_eq!(4, v[1].index);
    assert_eq!(vec![0x74, 0x65, 0x78, 0x74], v[2].word);
    assert_eq!(5, v[2].index);

    vm.set_byte(0x104, 0x2c)?; // ,
    let v = vm.split_text(0x100)?;
    assert_eq!(3, v.len());
    assert_eq!(vec![115, 111, 109, 101], v[0].word);
    assert_eq!(0, v[0].index);
    assert_eq!(vec![0x2c], v[1].word);
    assert_eq!(4, v[1].index);
    assert_eq!(vec![0x74, 0x65, 0x78, 0x74], v[2].word);
    assert_eq!(5, v[2].index);

    vm.set_byte(0x104, 0x2e)?; // .
    let v = vm.split_text(0x100)?;
    assert_eq!(3, v.len());
    assert_eq!(vec![115, 111, 109, 101], v[0].word);
    assert_eq!(0, v[0].index);
    assert_eq!(vec![0x2e], v[1].word);
    assert_eq!(4, v[1].index);
    assert_eq!(vec![0x74, 0x65, 0x78, 0x74], v[2].word);
    assert_eq!(5, v[2].index);

    // A separator char that's not part of the word is treated as part of the word
    vm.set_byte(0x104, 0x21)?; // !
    let v = vm.split_text(0x100)?;
    assert_eq!(1, v.len());
    assert_eq!(vec![115, 111, 109, 101, 33, 116, 101, 120, 116], v[0].word);
    assert_eq!(0, v[0].index);

    // Ignore spaces after a word separator
    vm.set_byte(0x104, 0x2e)?; // .
    vm.set_byte(0x105, 0x20)?; // space
    let v = vm.split_text(0x100)?;
    assert_eq!(3, v.len());
    assert_eq!(vec![115, 111, 109, 101], v[0].word);
    assert_eq!(0, v[0].index);
    assert_eq!(vec![0x2e], v[1].word);
    assert_eq!(4, v[1].index);
    assert_eq!(vec![0x65, 0x78, 0x74], v[2].word);
    assert_eq!(6, v[2].index);

    // Ignore mulltiple spacse
    vm.set_byte(0x104, 0x20)?; // .
    vm.set_byte(0x105, 0x20)?; // space
    let v = vm.split_text(0x100)?;
    assert_eq!(2, v.len());
    assert_eq!(vec![115, 111, 109, 101], v[0].word);
    assert_eq!(0, v[0].index);
    assert_eq!(vec![0x65, 0x78, 0x74], v[1].word);
    assert_eq!(6, v[1].index);

    // Another multiple space test - a  b , c
    vm.set_byte(0x100, 0x62)?;
    vm.set_byte(0x101, 0x20)?;
    vm.set_byte(0x102, 0x20)?;
    vm.set_byte(0x103, 0x63)?;
    vm.set_byte(0x104, 0x20)?;
    vm.set_byte(0x105, 0x2c)?;
    vm.set_byte(0x106, 0x20)?;
    vm.set_byte(0x107, 0x64)?;
    vm.set_byte(0x108, 0x00)?;
    let v = vm.split_text(0x100)?;
    assert_eq!(4, v.len());
    assert_eq!(vec![0x62], v[0].word);
    assert_eq!(0, v[0].index);
    assert_eq!(vec![0x63], v[1].word);
    assert_eq!(3, v[1].index);
    assert_eq!(vec![0x2c], v[2].word);
    assert_eq!(5, v[2].index);
    assert_eq!(vec![0x64], v[3].word);
    assert_eq!(7, v[3].index);

    Ok(())
}

#[test]
#[allow(clippy::cognitive_complexity)]
#[allow(clippy::char_lit_as_u8)]
fn test_dictionary_encode_and_lookup() -> Result<(), ZmachineError> {
    let vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic3), false, false)
        .expect("Error loading story");

    // word is "about"
    assert_eq!(
        [0x18, 0xF4, 0xEB, 0x25, 0x14, 0xa5],
        vm.dictionary_encode(vec![0x61, 0x62, 0x6f, 0x75, 0x74])
    );
    assert_eq!(
        Option::None,
        vm.dictionary_lookup(vec![0x61, 0x62, 0x6f, 0x75, 0x74])?
    );

    // word is "report"
    assert_eq!(
        [0x5d, 0x55, 0xd2, 0xf9, 0x14, 0xa5],
        vm.dictionary_encode(vec![0x72, 0x65, 0x70, 0x6f, 0x72, 0x74])
    );
    assert_eq!(
        Option::None,
        vm.dictionary_lookup(vec![0x72, 0x65, 0x70, 0x6f, 0x72, 0x74])?
    );

    // word is ","
    assert_eq!(
        [0x16, 0x65, 0x94, 0xA5, 0x14, 0xa5],
        vm.dictionary_encode(vec![0x2c])
    );
    assert_eq!(Option::None, vm.dictionary_lookup(vec![0x2c])?);

    // word is "i"
    assert_eq!(
        [0x38, 0xa5, 0x94, 0xa5, 0x14, 0xa5],
        vm.dictionary_encode(vec![0x69])
    );
    assert_eq!(Option::None, vm.dictionary_lookup(vec![0x69])?);

    // word is "ia"
    assert_eq!(
        [0x38, 0xC5, 0x94, 0xA5, 0x14, 0xa5],
        vm.dictionary_encode(vec![0x69, 0x61])
    );
    assert_eq!(Option::None, vm.dictionary_lookup(vec![0x69, 0x61])?);

    // word is "pup-per"
    assert_eq!(
        [0x57, 0x55, 0x97, 0x95, 0x28, 0xa5],
        vm.dictionary_encode(vec![0x70, 0x75, 0x70, 0x2d, 0x70, 0x65, 0x72])
    );
    assert_eq!(
        Option::None,
        vm.dictionary_lookup(vec![0x70, 0x75, 0x70, 0x2d, 0x70, 0x65, 0x72])?
    );

    // word is "13:43". This tests for overflow due to all the shifts
    assert_eq!(
        [21, 37, 172, 189, 21, 133],
        vm.dictionary_encode(vec![0x31, 0x33, 0x3a, 0x34, 0x33])
    );
    assert_eq!(
        Option::None,
        vm.dictionary_lookup(vec![0x31, 0x33, 0x3a, 0x34, 0x33])?
    );

    // word is "some"
    assert_eq!(
        [0x62, 0x92, 0xA8, 0xA5, 0x14, 0xa5],
        vm.dictionary_encode(vec![0x73, 0x6f, 0x6d, 0x65])
    );
    assert_eq!(
        Option::Some(DictionaryWord {
            address: 1289,
            text: String::from("some")
        }),
        vm.dictionary_lookup(vec![0x73, 0x6f, 0x6d, 0x65])?
    );

    // word is "more"
    assert_eq!(
        [0x4A, 0x97, 0xA8, 0xA5, 0x14, 0xa5],
        vm.dictionary_encode(vec![0x6d, 0x6f, 0x72, 0x65])
    );
    assert_eq!(
        Option::Some(DictionaryWord {
            address: 1282,
            text: String::from("more")
        }),
        vm.dictionary_lookup(vec![0x6d, 0x6f, 0x72, 0x65])?
    );

    // word is "text"
    assert_eq!(
        [0x65, 0x5D, 0xE4, 0xA5, 0x14, 0xa5],
        vm.dictionary_encode(vec![0x74, 0x65, 0x78, 0x74])
    );
    assert_eq!(
        Option::Some(DictionaryWord {
            address: 1296,
            text: String::from("text")
        }),
        vm.dictionary_lookup(vec![0x74, 0x65, 0x78, 0x74])?
    );

    // word is "TEXT"
    assert_eq!(
        [0x65, 0x5D, 0xE4, 0xA5, 0x14, 0xa5],
        vm.dictionary_encode(vec![0x54, 0x45, 0x58, 0x54])
    );
    assert_eq!(
        Option::Some(DictionaryWord {
            address: 1296,
            text: String::from("text")
        }),
        vm.dictionary_lookup(vec![0x54, 0x45, 0x58, 0x54])?
    );

    // These will encode differently in V1/V2
    assert_eq!(
        [56, 168, 184, 165, 20, 165],
        vm.dictionary_encode(vec![0x69, 0x30, 0x69])
    ); //i1i
    assert_eq!(
        [56, 168, 149, 37, 20, 165],
        vm.dictionary_encode(vec![0x69, 0x30, 0x31])
    ); //i01

    // test 3.7.1 (shift lock chars) in V1/V2
    // Use shift lock 4
    let vm = VM::create_from_story_bytes(load_test_story_data_v2(TestStory::Basic3), false, false)
        .expect("Error loading story");
    println!("-------");
    assert_eq!(
        [56, 104, 184, 165, 20, 165],
        vm.dictionary_encode(vec![0x69, 0x30, 0x69])
    ); //i1i
    assert_eq!(
        [56, 168, 164, 165, 20, 165],
        vm.dictionary_encode(vec![0x69, 0x30, 0x31])
    ); //i01
    Ok(())
}

#[test]
fn test_input_character_mapping() -> Result<(), ZmachineError> {
    let vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");

    let expected_input: [i32; 255] = [
        -1, -1, -1, -1, -1, -1, -1, -1, 8, -1, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, 27, -1, -1, -1, -1, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
        46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 97, 98, 99,
        100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
        118, 119, 120, 121, 122, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105,
        106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123,
        124, 125, 126, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    ];

    #[allow(clippy::needless_range_loop)]
    for i in 0..255 {
        let mapped = vm.utf_to_input_zscii(i as u8 as char);
        if expected_input[i] == -1 {
            assert_eq!(
                Err(ZmachineError::TextInvalidInputChar((i as u8) as char)),
                mapped,
                "For char {} expected error got {:?}",
                i,
                mapped
            );
        } else {
            assert_eq!(
                Ok(expected_input[i] as u8),
                mapped,
                "For char {} expected {} got {:?}",
                i,
                expected_input[i],
                mapped
            );
        }
    }

    Ok(())
}

#[test]

fn test_output_character_mapping() -> Result<(), ZmachineError> {
    let vm = VM::create_from_story_bytes(load_test_story_data(TestStory::Basic2), false, false)
        .expect("Error loading story");
    let expected_output: [Result<char, ZmachineError>; 255] = [
        Ok('\0'),
        Err(ZmachineError::TextInvalidOutputChar(1)),
        Err(ZmachineError::TextInvalidOutputChar(2)),
        Err(ZmachineError::TextInvalidOutputChar(3)),
        Err(ZmachineError::TextInvalidOutputChar(4)),
        Err(ZmachineError::TextInvalidOutputChar(5)),
        Err(ZmachineError::TextInvalidOutputChar(6)),
        Err(ZmachineError::TextInvalidOutputChar(7)),
        Err(ZmachineError::TextInvalidOutputChar(8)),
        Err(ZmachineError::TextInvalidOutputChar(9)),
        Ok('\n'),
        Err(ZmachineError::TextInvalidOutputChar(11)),
        Err(ZmachineError::TextInvalidOutputChar(12)),
        Err(ZmachineError::TextInvalidOutputChar(13)),
        Err(ZmachineError::TextInvalidOutputChar(14)),
        Err(ZmachineError::TextInvalidOutputChar(15)),
        Err(ZmachineError::TextInvalidOutputChar(16)),
        Err(ZmachineError::TextInvalidOutputChar(17)),
        Err(ZmachineError::TextInvalidOutputChar(18)),
        Err(ZmachineError::TextInvalidOutputChar(19)),
        Err(ZmachineError::TextInvalidOutputChar(20)),
        Err(ZmachineError::TextInvalidOutputChar(21)),
        Err(ZmachineError::TextInvalidOutputChar(22)),
        Err(ZmachineError::TextInvalidOutputChar(23)),
        Err(ZmachineError::TextInvalidOutputChar(24)),
        Err(ZmachineError::TextInvalidOutputChar(25)),
        Err(ZmachineError::TextInvalidOutputChar(26)),
        Err(ZmachineError::TextInvalidOutputChar(27)),
        Err(ZmachineError::TextInvalidOutputChar(28)),
        Err(ZmachineError::TextInvalidOutputChar(29)),
        Err(ZmachineError::TextInvalidOutputChar(30)),
        Err(ZmachineError::TextInvalidOutputChar(31)),
        Ok(' '),
        Ok('!'),
        Ok('"'),
        Ok('#'),
        Ok('$'),
        Ok('%'),
        Ok('&'),
        Ok('\''),
        Ok('('),
        Ok(')'),
        Ok('*'),
        Ok('+'),
        Ok(','),
        Ok('-'),
        Ok('.'),
        Ok('/'),
        Ok('0'),
        Ok('1'),
        Ok('2'),
        Ok('3'),
        Ok('4'),
        Ok('5'),
        Ok('6'),
        Ok('7'),
        Ok('8'),
        Ok('9'),
        Ok(':'),
        Ok(';'),
        Ok('<'),
        Ok('='),
        Ok('>'),
        Ok('?'),
        Ok('@'),
        Ok('A'),
        Ok('B'),
        Ok('C'),
        Ok('D'),
        Ok('E'),
        Ok('F'),
        Ok('G'),
        Ok('H'),
        Ok('I'),
        Ok('J'),
        Ok('K'),
        Ok('L'),
        Ok('M'),
        Ok('N'),
        Ok('O'),
        Ok('P'),
        Ok('Q'),
        Ok('R'),
        Ok('S'),
        Ok('T'),
        Ok('U'),
        Ok('V'),
        Ok('W'),
        Ok('X'),
        Ok('Y'),
        Ok('Z'),
        Ok('['),
        Ok('\\'),
        Ok(']'),
        Ok('^'),
        Ok('_'),
        Ok('`'),
        Ok('a'),
        Ok('b'),
        Ok('c'),
        Ok('d'),
        Ok('e'),
        Ok('f'),
        Ok('g'),
        Ok('h'),
        Ok('i'),
        Ok('j'),
        Ok('k'),
        Ok('l'),
        Ok('m'),
        Ok('n'),
        Ok('o'),
        Ok('p'),
        Ok('q'),
        Ok('r'),
        Ok('s'),
        Ok('t'),
        Ok('u'),
        Ok('v'),
        Ok('w'),
        Ok('x'),
        Ok('y'),
        Ok('z'),
        Ok('{'),
        Ok('|'),
        Ok('}'),
        Ok('~'),
        Err(ZmachineError::TextInvalidOutputChar(127)),
        Err(ZmachineError::TextInvalidOutputChar(128)),
        Err(ZmachineError::TextInvalidOutputChar(129)),
        Err(ZmachineError::TextInvalidOutputChar(130)),
        Err(ZmachineError::TextInvalidOutputChar(131)),
        Err(ZmachineError::TextInvalidOutputChar(132)),
        Err(ZmachineError::TextInvalidOutputChar(133)),
        Err(ZmachineError::TextInvalidOutputChar(134)),
        Err(ZmachineError::TextInvalidOutputChar(135)),
        Err(ZmachineError::TextInvalidOutputChar(136)),
        Err(ZmachineError::TextInvalidOutputChar(137)),
        Err(ZmachineError::TextInvalidOutputChar(138)),
        Err(ZmachineError::TextInvalidOutputChar(139)),
        Err(ZmachineError::TextInvalidOutputChar(140)),
        Err(ZmachineError::TextInvalidOutputChar(141)),
        Err(ZmachineError::TextInvalidOutputChar(142)),
        Err(ZmachineError::TextInvalidOutputChar(143)),
        Err(ZmachineError::TextInvalidOutputChar(144)),
        Err(ZmachineError::TextInvalidOutputChar(145)),
        Err(ZmachineError::TextInvalidOutputChar(146)),
        Err(ZmachineError::TextInvalidOutputChar(147)),
        Err(ZmachineError::TextInvalidOutputChar(148)),
        Err(ZmachineError::TextInvalidOutputChar(149)),
        Err(ZmachineError::TextInvalidOutputChar(150)),
        Err(ZmachineError::TextInvalidOutputChar(151)),
        Err(ZmachineError::TextInvalidOutputChar(152)),
        Err(ZmachineError::TextInvalidOutputChar(153)),
        Err(ZmachineError::TextInvalidOutputChar(154)),
        Ok('ä'),
        Ok('ö'),
        Ok('ü'),
        Ok('Ä'),
        Ok('Ö'),
        Ok('Ü'),
        Ok('ß'),
        Ok('»'),
        Ok('«'),
        Ok('ë'),
        Ok('ï'),
        Ok('ÿ'),
        Ok('Ë'),
        Ok('Ï'),
        Ok('á'),
        Ok('é'),
        Ok('í'),
        Ok('ó'),
        Ok('ú'),
        Ok('ý'),
        Ok('Á'),
        Ok('É'),
        Ok('Í'),
        Ok('Ó'),
        Ok('Ú'),
        Ok('Ý'),
        Ok('à'),
        Ok('è'),
        Ok('ì'),
        Ok('ò'),
        Ok('ù'),
        Ok('À'),
        Ok('È'),
        Ok('Ì'),
        Ok('Ò'),
        Ok('Ù'),
        Ok('â'),
        Ok('ê'),
        Ok('î'),
        Ok('ô'),
        Ok('û'),
        Ok('Â'),
        Ok('Ê'),
        Ok('Î'),
        Ok('Ô'),
        Ok('Û'),
        Ok('å'),
        Ok('Å'),
        Ok('ø'),
        Ok('Ø'),
        Ok('ã'),
        Ok('ñ'),
        Ok('õ'),
        Ok('Ã'),
        Ok('Ñ'),
        Ok('Õ'),
        Ok('æ'),
        Ok('Æ'),
        Ok('ç'),
        Ok('Ç'),
        Ok('þ'),
        Ok('ð'),
        Ok('Þ'),
        Ok('Ð'),
        Ok('£'),
        Ok('œ'),
        Ok('Œ'),
        Ok('¡'),
        Ok('¿'),
        Err(ZmachineError::TextInvalidOutputChar(224)),
        Err(ZmachineError::TextInvalidOutputChar(225)),
        Err(ZmachineError::TextInvalidOutputChar(226)),
        Err(ZmachineError::TextInvalidOutputChar(227)),
        Err(ZmachineError::TextInvalidOutputChar(228)),
        Err(ZmachineError::TextInvalidOutputChar(229)),
        Err(ZmachineError::TextInvalidOutputChar(230)),
        Err(ZmachineError::TextInvalidOutputChar(231)),
        Err(ZmachineError::TextInvalidOutputChar(232)),
        Err(ZmachineError::TextInvalidOutputChar(233)),
        Err(ZmachineError::TextInvalidOutputChar(234)),
        Err(ZmachineError::TextInvalidOutputChar(235)),
        Err(ZmachineError::TextInvalidOutputChar(236)),
        Err(ZmachineError::TextInvalidOutputChar(237)),
        Err(ZmachineError::TextInvalidOutputChar(238)),
        Err(ZmachineError::TextInvalidOutputChar(239)),
        Err(ZmachineError::TextInvalidOutputChar(240)),
        Err(ZmachineError::TextInvalidOutputChar(241)),
        Err(ZmachineError::TextInvalidOutputChar(242)),
        Err(ZmachineError::TextInvalidOutputChar(243)),
        Err(ZmachineError::TextInvalidOutputChar(244)),
        Err(ZmachineError::TextInvalidOutputChar(245)),
        Err(ZmachineError::TextInvalidOutputChar(246)),
        Err(ZmachineError::TextInvalidOutputChar(247)),
        Err(ZmachineError::TextInvalidOutputChar(248)),
        Err(ZmachineError::TextInvalidOutputChar(249)),
        Err(ZmachineError::TextInvalidOutputChar(250)),
        Err(ZmachineError::TextInvalidOutputChar(251)),
        Err(ZmachineError::TextInvalidOutputChar(252)),
        Err(ZmachineError::TextInvalidOutputChar(253)),
        Err(ZmachineError::TextInvalidOutputChar(254)),
    ];

    for i in 0..255 {
        let mapped = vm.zscii_to_output_char(i);
        assert_eq!(
            expected_output[i as usize], mapped,
            "For char {} expected {:?} got {:?}",
            i, expected_output[i as usize], mapped
        );
    }

    Ok(())
}

const MAX_INSTRUCTIONS_CZECH: usize = 100_000;

#[test]
// Run tests using the czech.v3 unit tests
fn test_with_czech_v3() -> Result<(), ZmachineError> {
    let mut io = DebugIO::create();
    let mut vm = VM::create_from_story_bytes(load_czech(), false, false).expect("Loading story");
    vm.reseed_rng_predicable(1);
    //vm.set_debug_verbosity(DebugVerbosity::All);

    let mut counter = 0;

    while vm.get_state() == VMState::Running {
        counter += 1;
        if counter >= MAX_INSTRUCTIONS_CZECH {
            panic!(
                "Possible infinite loop -- executed {} instructions without switching state.",
                counter
            );
        }

        vm.tick(&mut io);
    }
    assert_eq!(VMState::Quit, vm.get_state());
    let text = io.get_text_buffer().clone();
    assert_eq!(None, text.find("ERROR"));
    assert!(text.contains("Failed: 0"));
    Ok(())
}

#[test]
fn test_iff_load() {
    // Test the data loaded from a sample save file. This is based off the "cabin"
    // game I was writing
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("resources");
    d.push("iff");
    d.push("sample.sav");

    let data = fs::read(d.as_os_str()).expect("Error loading test story file 'basic.z3'.");
    let chunks = load_iff_chunks_from_bytes(&data).expect("Error loading IFF chunks");
    assert_eq!(1, chunks.len());
    if let IffChunk::FORM(chunk_id, form_chunks) = &chunks[0] {
        assert_eq!("IFZS", get_chunk_id_as_str(chunk_id));
        assert_eq!(4, form_chunks.len());

        if let IffChunk::IFhd {
            release_number,
            serial_number,
            checksum,
            initial_pc,
        } = &form_chunks[0]
        {
            assert_eq!(1, *release_number);
            assert_eq!(vec![50, 48, 48, 55, 48, 56], *serial_number);
            assert_eq!(0xd46b, *checksum);
            assert_eq!(0xe358, *initial_pc);
        } else {
            panic!("First chunk should be an IFhd");
        }

        if let IffChunk::IntD {
            os_id,
            flags,
            contents_id,
            reserved,
            interpreter_id,
            data,
        } = &form_chunks[1]
        {
            assert_eq!("UNIX", get_chunk_id_as_str(os_id));
            assert_eq!(2, *flags);
            assert_eq!(0, *contents_id);
            assert_eq!(0, *reserved);
            assert_eq!(vec![32, 32, 32, 32], *interpreter_id);
            assert_eq!(30, data.len());
        } else {
            panic!("Second chunk should be an IFhd");
        }

        if let IffChunk::CMem(data) = &form_chunks[2] {
            assert_eq!(614, data.len());
        } else {
            panic!("Third chunk should be CMem");
        }

        if let IffChunk::Stks(frames) = &form_chunks[3] {
            assert_eq!(8, frames.len());

            let frame = &frames[0];
            assert_eq!(0, frame.return_pc);
            assert_eq!(0, frame.flags);
            assert_eq!(0, frame.result_var);
            assert_eq!(0, frame.arguments);
            assert_eq!(0, frame.local_variables.len());
            assert_eq!(0, frame.evaluation_stack.len());

            let frame = &frames[5];
            assert_eq!(0x11d34, frame.return_pc);
            assert_eq!(7, frame.flags);
            assert_eq!(0x0b, frame.result_var);
            assert_eq!(0x0f, frame.arguments);
            assert_eq!(vec![61, 0, 0, 0, 61, 0, 0], frame.local_variables);
            assert_eq!(0, frame.evaluation_stack.len());

            let frame = &frames[7];
            assert_eq!(0xAEEB, frame.return_pc);
            assert_eq!(17, frame.flags);
            assert_eq!(0, frame.result_var);
            assert_eq!(0, frame.arguments);
            assert_eq!(vec![0], frame.local_variables);
            assert_eq!(0, frame.evaluation_stack.len());
        } else {
            panic!("Fourth chunk should be Stks");
        }
    } else {
        panic!("Expected first item to be FORM");
    }
}

#[test]
fn test_iff_save() {
    // Load a save, then save it again, and make sure data matches
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("resources");
    d.push("iff");
    d.push("sample.sav");

    let data = fs::read(d.as_os_str()).expect("Error loading test story file 'basic.z3'.");
    let chunks_in = load_iff_chunks_from_bytes(&data).expect("Error loading IFF chunks");
    let chunks_out = save_iff_chunks_to_bytes(chunks_in).expect("Error saving IFF chunks");
    assert_eq!(data, chunks_out);
}
