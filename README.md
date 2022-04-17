# ferrif-zmachine

Z-Machine interpreter written in Rust

Throughout the documentation you will see references to the core ZMachine spec. Eg 1.1 refers to the first requirement in the spec at https://www.inform-fiction.org/zmachine/standards/z1point1/sect01.html

# Goals

There are no shortage of Z-Machines implementations out there. Ferrif has four goals:

1) To provide a project to learn Rust
2) To build a project from a spec
3) To work cross-platform
4) To provide tools and scaffolding for playing classic Infocom games

The latter goal in particular means that it has features that may not be useful/relevant for more modern IF.

# Building an Interpreter

This project is a Z-machine abstracted from any IO. It is defined to be used as part of an interpreter, such as the main ferrif interpreter.

The core struct is the `VM`. A `VM` is initialized by calling the `create_from_story_bytes` method. This returns a `Result` where `Ok` will contain the valid `VM` object and an `Err` if not valid. 
 
The VM has an internal state that can be accessed by calling `vm.get_state()`. 

Interpreters must call the `vm.tick` function in their main loop. This takes a `TerpIO` trait reference and processes a single instruction, modifying the internal state and calling functions on the `TerpIO` referenced as needed. 

Overall, to have a fully functioning interpreter, the only requirements are:
- Have an implementation of a `TerpIO` trait
- Call `tick`
- Handle any interpter states that may require action from the player (eg `SavePrompt`)

# TerpIO

The TerpIO (contained in the `interfaces` module) is the interface from the VM to the broader world. It handles both input/output itself as well as letting the VM know about the capabilities of IO.

This trait does not directly handle saves or loads. The interpter can handle those by monitoring the VM state and seeing when it moves into save/restore prompt states.

## Capabilities

- `fn supports_transcript(&self) -> bool`: return true if this interpreter supports transcripts
- `fn supports_commands_output(&self) -> bool`: return true if this interpreter supports the command output stream
- `fn supports_commands_input(&self) -> bool`: return true if this interpreter supports the command input stream

## Screen

- `fn set_screen_output(&mut self, v: bool)`: set whether screen output should be active or not
- `fn is_screen_output_active(&self) -> bool`: return whether the screen output stream is currently active 

## Screen output

See https://www.inform-fiction.org/zmachine/standards/z1point1/sect08.html

- `fn print_to_screen(&mut self, s: &str)`: print the string to the screen
- `fn print_char(&mut self, c: char)`: print the unicode char `c` to the screen
- `fn draw_status(&mut self, left: &str, right: &str)`: draw the status bar with the specified text for left/right sides

- `fn split_window(&mut self, lines: usize)`: split the screen into two windows with top window of height `lines`

## Screen and command input

See https://www.inform-fiction.org/zmachine/standards/z1point1/sect10.html

- `fn waiting_for_input(&self) -> bool`: return whether the intepreter is waiting for input from the player. If tick is called in the `WaitingForInput` state, this being true lets the VM know to handle whatever text player entered
- `fn last_input(&mut self) -> String`: return the last text entered by the player
- `fn wait_for_line(&mut self, max_input_length: usize`: tell the interpeter to start collecting a line of text from the player of max length `max_input_length`
- `fn set_command_input(&mut self, v: bool)`: toggle reading from the command input stream on/off
- `fn is_reading_from_commands(&self) -> bool`: return whether the command input stream is currently active

## Transcript and command output

See https://www.inform-fiction.org/zmachine/standards/z1point1/sect07.html

- `fn is_transcript_active(&self) -> bool`: return whether the transcript stream is currently active
- `fn set_transcript(&mut self, v: bool)`: toggle the transcript stream on/off
- `fn print_to_transcript(&mut self, s: &str)`: output a string to the transcript
- `fn is_command_output_active(&self) -> bool`: return whether the command output stream is active or not
- `fn set_command_output(&mut self, v: bool)`: toggle the command output stream on/off
- `fn print_to_commands(&mut self, s: &str)`: output a string to the command stream

## Misc
- `fn recalculate_and_redraw(&mut self, force: bool);`: force a redraw of the screen, recalculating any bounds
- `fn play_sound_effect(&mut self, sound: u16, effect: u16, volume: u16)`: play a sound (see https://www.inform-fiction.org/zmachine/standards/z1point1/sect09.html)

# VM Architecture

This struct contains memory, state, call stack, variables as well as helper methods. The ZMachine architecture is tightly coupled  (ie printing a string can involve scanning memory until a specific byte is found, then looking up abbreviations in another part of memory).

A `VM` is initialized by calling the `create_from_story_bytes` method. This returns a `Result` where `Ok` will contain the valid `VM` object and an `Err` if not valid. Possible errors includes:
- Empty data
- File size issue (see 1.1.4)
- Invalid header

A `VM` struct contains the following key information. None of it is directly accessible 
- `version`, the Z-Machine version of this story file. Needed to modify behavior based on version
- `story` is a byte vector containing the untouched original story file data. This is kept separately to make it easy to reload/restart
without having to reopen the story file
- `memory` is a byte vector that will be mutated as the game plays.
- `routine_stack` is a vector of `Routine` structs that maintain the call stack of the intepreter
- `state` is the current state of the interpreter
- `pc` is the stack pointer
- `rng` contains the current random number generator for the VM.

It also contains several fields (such as `high_memory_address`) that are immutable and pulled from the story header for reference.

### MemoryReader

Rather than access the interpreter directly, access methods are used, as defined in the `MemoryReader` trait. These allow for getting and setting bits, bytes, words (2 bytes), byte arrays, all with bounds checks. 

A `MemoryReader` also supports conversion of packed addresses (see 1.2.3) and getting/peeking specific "variables", which based on the variable number in the spec can include the stack, local variables, and global variables stored in memory.

### ObjectTreeReader

See https://www.inform-fiction.org/zmachine/standards/z1point1/sect12.html

This trait provides convienience methods for working with objects. The object tree is still stored entirely in game memory and is not stored in an intermediate structure.

### States

The internal states of the VM are:

- `Initializing`: VM has been created but never run
- `Running`: VM is running through instructions
- `WaitingForInput`: VM has processed a `read` or related instruction and is waiting for input from the player
- `RestorePrompt`: VM processed a `restore` instruction and user must choose a game to restore
- `SavePrompt`: VM processed a `save` instruction and user must choose a place to store the save
- `TranscriptPrompt`: VM processed an instruction that turned on the transcript screen and is waiting for information on the stream
- `CommandOutputPrompt`: VM processed an instruction that turned on the command output screen and is waiting for information on the stream
- `CommandInputPrompt`: VM processed an instruction that turned on the command input screen and is waiting for information on the stream
- `Quit`: VM processed a quit instruction
- `Error`: VM has hit an error processing instructions and halted

### Text

See https://www.inform-fiction.org/zmachine/standards/z1point1/sect03.html

The text output subsystem converts the two-byte ZSCII text into UTF that can then be printed to the screen. This process is dependent on both the game memory (for finding end of text and abbreviations/alphabet tables) as well as the ZMachine version. 

All conversion starts with a memory location containing the text. To convert text, call :

`text_to_utf(addr,length) -> Result(String)`

where addr is the starting point of the text, and length is the expected length (in words). If length is 0, it will return text until it finds an end bit set.

This method will:
- Select the appropriate alphabet table based on version
- Starting at addr, iterate until length hit or end bit is set, extracting two words at a time
- Convert those two words into three ZSCII chars
- Convert the ZSCII chars to UTF, using the alphabet table and abbreviation lookups
