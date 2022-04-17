use crate::instructions::{InputStreamEnum, WindowLayout};
use crate::quetzal::iff::QueztalStackFrame;

/// Wraps data used to save/restore
/// See section 5.1 of the Quetzal format
pub struct QuetzalData {
    pub release_number: u16,
    pub serial: [u8; 6],
    pub checksum: u16,
    pub initial_pc: usize,
    pub stack_frames: Vec<QueztalStackFrame>,
    pub data: Vec<u8>,
    pub data_is_compressed: bool,
}

impl Clone for QuetzalData {
    fn clone(&self) -> QuetzalData {
        QuetzalData {
            release_number: self.release_number,
            checksum: self.checksum,
            serial: self.serial,
            initial_pc: self.initial_pc,
            data: self.data.clone(),
            data_is_compressed: self.data_is_compressed,
            stack_frames: self.stack_frames.clone(),
        }
    }
}

/// Handles any IO for a terp
/// Note that none of the output methods return Result -- any failure on right
/// will be handled by the terp itself, and the VM can be ignorant
pub trait TerpIO {
    fn print_char(&mut self, c: char);
    fn draw_status(&mut self, left: &str, right: &str);

    fn split_window(&mut self, lines: usize);
    fn set_window(&mut self, window: WindowLayout);

    fn print_to_screen(&mut self, s: &str);

    // Return true if waiting for input, false otherwise
    fn waiting_for_input(&self) -> bool;

    // Return last input entered by player.
    fn last_input(&mut self) -> String;

    // Wait for a whole line, up to a length of max_input_length
    fn wait_for_line(&mut self, max_input_length: usize);

    fn recalculate_and_redraw(&mut self, force: bool);

    // Input and output streams
    fn is_screen_output_active(&self) -> bool;
    fn set_screen_output(&mut self, v: bool);

    fn supports_transcript(&self) -> bool;
    fn is_transcript_active(&self) -> bool;
    fn set_transcript(&mut self, v: bool);
    fn print_to_transcript(&mut self, s: &str);

    fn supports_commands_output(&self) -> bool;
    fn is_command_output_active(&self) -> bool;
    fn set_command_output(&mut self, v: bool);
    fn print_to_commands(&mut self, s: &str);

    fn supports_commands_input(&self) -> bool;
    fn set_command_input(&mut self, v: bool);
    fn is_reading_from_commands(&self) -> bool;

    fn play_sound_effect(&mut self, sound: u16, effect: u16, volume: u16);
}

///
/// TerpIO implementation that (optionally) stores text in a vector
/// Used for debug/initialization purposes
///
pub struct DebugIO {
    text_buffer: String,
    store_text: bool,
    pub status_left: String,
    pub status_right: String,
    pub input_stream: InputStreamEnum,
    pub screen_output_active: bool,
    pub window: WindowLayout,
    pub upper_window_lines: usize,
    pub sound_number: u16,
    pub sound_effect: u16,
    pub sound_volume: u16,
    command_output_active: bool,
    transcript_active: bool,
    waiting_for_line: bool,
    // When set, panic if anything printed to output stream
    pub panic_on_output: bool,
}

impl DebugIO {
    pub fn create() -> DebugIO {
        DebugIO {
            text_buffer: String::new(),
            store_text: true,
            status_left: String::new(),
            status_right: String::new(),
            input_stream: InputStreamEnum::Keyboard,
            screen_output_active: true,
            window: WindowLayout::Lower,
            upper_window_lines: 0,
            sound_number: 0,
            sound_effect: 0,
            sound_volume: 0,
            command_output_active: false,
            transcript_active: false,
            waiting_for_line: false,
            panic_on_output: false,
        }
    }

    pub fn get_text_buffer(self) -> String {
        self.text_buffer
    }
}

impl TerpIO for DebugIO {
    fn play_sound_effect(&mut self, sound: u16, effect: u16, volume: u16) {
        self.sound_number = sound;
        self.sound_effect = effect;
        self.sound_volume = volume;
    }

    fn recalculate_and_redraw(&mut self, _force: bool) {}

    fn waiting_for_input(&self) -> bool {
        self.waiting_for_line
    }
    fn last_input(&mut self) -> String {
        String::new()
    }
    fn wait_for_line(&mut self, _: usize) {
        self.waiting_for_line = true;
    }

    fn print_char(&mut self, c: char) {
        if self.store_text {
            self.text_buffer.push(c);
        }
    }

    fn draw_status(&mut self, left: &str, right: &str) {
        self.status_left.clear();
        self.status_left.push_str(left);
        self.status_right.clear();
        self.status_right.push_str(right);
    }

    fn split_window(&mut self, lines: usize) {
        self.upper_window_lines = lines;
    }

    fn set_window(&mut self, window: WindowLayout) {
        self.window = window;
    }

    fn print_to_transcript(&mut self, s: &str) {
        if self.panic_on_output {
            panic!("Print '{}' to transcript when panic_on_output set", s);
        }
    }
    fn print_to_commands(&mut self, s: &str) {
        if self.panic_on_output {
            panic!("Print '{}' to commands when panic_on_output set", s);
        }
    }
    fn print_to_screen(&mut self, s: &str) {
        if self.panic_on_output {
            panic!("Print '{}' to screen when panic_on_output set", s);
        }

        if self.store_text {
            for c in s.chars() {
                self.text_buffer.push(c);
            }
        }
    }

    fn supports_transcript(&self) -> bool {
        true
    }
    fn supports_commands_output(&self) -> bool {
        true
    }
    fn supports_commands_input(&self) -> bool {
        true
    }
    fn is_transcript_active(&self) -> bool {
        self.transcript_active
    }
    fn is_command_output_active(&self) -> bool {
        self.command_output_active
    }
    fn is_reading_from_commands(&self) -> bool {
        false
    }
    fn is_screen_output_active(&self) -> bool {
        self.screen_output_active
    }
    fn set_transcript(&mut self, b: bool) {
        self.transcript_active = b;
    }

    fn set_screen_output(&mut self, b: bool) {
        self.screen_output_active = b;
    }

    fn set_command_input(&mut self, b: bool) {
        self.input_stream = match b {
            true => InputStreamEnum::File,
            false => InputStreamEnum::Keyboard,
        };
    }
    fn set_command_output(&mut self, b: bool) {
        self.command_output_active = b;
    }
}
