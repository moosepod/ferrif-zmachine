#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum StatusMode {
    Score,
    Time,
}

//
// Text
//
pub const NOPRINT_CHAR: u8 = 0;
pub const ABBREV_1: u8 = 1;
pub const ABBREV_2: u8 = 2;
pub const ABBREV_3: u8 = 3;
pub const TOGGLE_EXTENDED: u8 = 6;

const SHIFT_UP: u8 = 2;
pub const SHIFT_DOWN: u8 = 3;
pub const SHIFT_LOCK_UP: u8 = 4;
pub const SHIFT_LOCK_DOWN: u8 = 5;

pub static DEFAULT_UNICODE_MAPPING: [char; 69] = [
    'ä', 'ö', 'ü', 'Ä', 'Ö', 'Ü', 'ß', '»', '«', 'ë', 'ï', 'ÿ', 'Ë', 'Ï', 'á', 'é', 'í', 'ó', 'ú',
    'ý', 'Á', 'É', 'Í', 'Ó', 'Ú', 'Ý', 'à', 'è', 'ì', 'ò', 'ù', 'À', 'È', 'Ì', 'Ò', 'Ù', 'â', 'ê',
    'î', 'ô', 'û', 'Â', 'Ê', 'Î', 'Ô', 'Û', 'å', 'Å', 'ø', 'Ø', 'ã', 'ñ', 'õ', 'Ã', 'Ñ', 'Õ', 'æ',
    'Æ', 'ç', 'Ç', 'þ', 'ð', 'Þ', 'Ð', '£', 'œ', 'Œ', '¡', '¿',
];

// A0 is a-z
pub static A0_CHARS: [u8; 32] = [
    32, 0, 0, 0, 0, 0, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
    113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
];
// A1 is    A-Z
static A1_CHARS: [u8; 32] = [
    32, 0, 0, 0, 0, 0, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83,
    84, 85, 86, 87, 88, 89, 90,
];

// A2 is  ^0123456789.,!?_#'"/\-:()
pub static A2_CHARS: [u8; 32] = [
    32,
    0,
    0,
    0,
    0,
    0,
    TOGGLE_EXTENDED,
    10,
    48,
    49,
    50,
    51,
    52,
    53,
    54,
    55,
    56,
    57,
    46,
    44,
    33,
    63,
    95,
    35,
    39,
    34,
    47,
    92,
    45,
    58,
    40,
    41,
];

// A2 variant for version 1 is 0123456789.,!?_#'"/\<-:()
static A2_V1_CHARS: [u8; 32] = [
    32, 0, 0, 0, 0, 0, 32, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 46, 44, 33, 63, 95, 35, 39, 34,
    47, 92, 60, 45, 58, 40, 41,
];

#[derive(Copy, Clone)]
pub enum Alphabet {
    A0,
    A1,
    A2,
}

pub trait ZCharacterMapper {
    fn map(&mut self, zc: u8) -> u8;
    fn reset(&mut self);
    fn preserve_state(&mut self);
    fn restore_state(&mut self);
}

// Stub mapper -- panics when used
pub struct ZCharacterMapperStub {}

impl ZCharacterMapperStub {
    pub fn create() -> ZCharacterMapperStub {
        ZCharacterMapperStub {}
    }
}

impl ZCharacterMapper for ZCharacterMapperStub {
    fn map(&mut self, _: u8) -> u8 {
        panic!("Mapper not supported");
    }

    fn reset(&mut self) {
        panic!("Mapper not supported");
    }

    fn preserve_state(&mut self) {
        panic!("Mapper not supported");
    }

    fn restore_state(&mut self) {
        panic!("Mapper not supported");
    }
}

// V1 mapper
pub struct ZCharacterMapperV1 {
    alphabet: Alphabet,
    next_alphabet: Alphabet,
    preserved: Alphabet,
    preserved_next: Alphabet,
}

impl ZCharacterMapperV1 {
    pub fn create() -> ZCharacterMapperV1 {
        ZCharacterMapperV1 {
            alphabet: Alphabet::A0,
            next_alphabet: Alphabet::A0,
            preserved: Alphabet::A0,
            preserved_next: Alphabet::A0,
        }
    }
}

impl ZCharacterMapper for ZCharacterMapperV1 {
    fn reset(&mut self) {
        self.alphabet = Alphabet::A0;
        self.next_alphabet = self.alphabet;
    }

    fn preserve_state(&mut self) {
        self.preserved = self.alphabet;
        self.preserved_next = self.next_alphabet;
    }

    fn restore_state(&mut self) {
        self.alphabet = self.preserved;
        self.next_alphabet = self.preserved_next;
    }

    fn map(&mut self, zc: u8) -> u8 {
        if zc > 31 {
            return NOPRINT_CHAR;
        }

        if zc == ABBREV_1 {
            return b'\n';
        }

        match zc {
            SHIFT_UP => {
                self.next_alphabet = self.alphabet; // preserve current alphabet
                match self.alphabet {
                    Alphabet::A0 => {
                        self.alphabet = Alphabet::A1;
                    }
                    Alphabet::A1 => {
                        self.alphabet = Alphabet::A2;
                    }
                    Alphabet::A2 => {
                        self.alphabet = Alphabet::A0;
                    }
                }
                NOPRINT_CHAR
            }
            SHIFT_LOCK_UP => {
                match self.alphabet {
                    Alphabet::A0 => {
                        self.alphabet = Alphabet::A1;
                    }
                    Alphabet::A1 => {
                        self.alphabet = Alphabet::A2;
                    }
                    Alphabet::A2 => {
                        self.alphabet = Alphabet::A0;
                    }
                }
                self.next_alphabet = self.alphabet; // shift is permanent
                NOPRINT_CHAR
            }
            SHIFT_DOWN => {
                self.next_alphabet = self.alphabet; // preserve current alphabet
                match self.alphabet {
                    Alphabet::A0 => {
                        self.alphabet = Alphabet::A2;
                    }
                    Alphabet::A1 => {
                        self.alphabet = Alphabet::A0;
                    }
                    Alphabet::A2 => {
                        self.alphabet = Alphabet::A1;
                    }
                }
                NOPRINT_CHAR
            }
            SHIFT_LOCK_DOWN => {
                match self.alphabet {
                    Alphabet::A0 => {
                        self.alphabet = Alphabet::A2;
                    }
                    Alphabet::A1 => {
                        self.alphabet = Alphabet::A0;
                    }
                    Alphabet::A2 => {
                        self.alphabet = Alphabet::A1;
                    }
                }
                self.next_alphabet = self.alphabet; // shift is permanent
                NOPRINT_CHAR
            }
            _ => match self.alphabet {
                Alphabet::A0 => {
                    self.alphabet = self.next_alphabet;
                    A0_CHARS[zc as usize]
                }
                Alphabet::A1 => {
                    self.alphabet = self.next_alphabet;
                    A1_CHARS[zc as usize]
                }
                Alphabet::A2 => {
                    self.alphabet = self.next_alphabet;
                    A2_V1_CHARS[zc as usize]
                }
            },
        }
    }
}

// V2 mapper
pub struct ZCharacterMapperV2 {
    alphabet: Alphabet,
    next_alphabet: Alphabet,
    preserved: Alphabet,
    preserved_next: Alphabet,
}

impl ZCharacterMapperV2 {
    pub fn create() -> ZCharacterMapperV2 {
        ZCharacterMapperV2 {
            alphabet: Alphabet::A0,
            next_alphabet: Alphabet::A0,
            preserved: Alphabet::A0,
            preserved_next: Alphabet::A0,
        }
    }
}

impl ZCharacterMapper for ZCharacterMapperV2 {
    fn reset(&mut self) {
        self.alphabet = Alphabet::A0;
        self.next_alphabet = self.alphabet;
    }

    fn preserve_state(&mut self) {
        self.preserved = self.alphabet;
        self.preserved_next = self.next_alphabet;
    }

    fn restore_state(&mut self) {
        self.alphabet = self.preserved;
        self.next_alphabet = self.preserved_next;
    }

    fn map(&mut self, zc: u8) -> u8 {
        if zc > 31 {
            return NOPRINT_CHAR;
        }

        if zc == ABBREV_1 {
            return ABBREV_1;
        }

        match zc {
            SHIFT_UP => {
                self.next_alphabet = self.alphabet; // preserve current alphabet
                match self.alphabet {
                    Alphabet::A0 => {
                        self.alphabet = Alphabet::A1;
                    }
                    Alphabet::A1 => {
                        self.alphabet = Alphabet::A2;
                    }
                    Alphabet::A2 => {
                        self.alphabet = Alphabet::A0;
                    }
                }
                NOPRINT_CHAR
            }
            SHIFT_LOCK_UP => {
                match self.alphabet {
                    Alphabet::A0 => {
                        self.alphabet = Alphabet::A1;
                    }
                    Alphabet::A1 => {
                        self.alphabet = Alphabet::A2;
                    }
                    Alphabet::A2 => {
                        self.alphabet = Alphabet::A0;
                    }
                }
                self.next_alphabet = self.alphabet; // shift is permanent
                NOPRINT_CHAR
            }
            SHIFT_DOWN => {
                self.next_alphabet = self.alphabet; // preserve current alphabet
                match self.alphabet {
                    Alphabet::A0 => {
                        self.alphabet = Alphabet::A2;
                    }
                    Alphabet::A1 => {
                        self.alphabet = Alphabet::A0;
                    }
                    Alphabet::A2 => {
                        self.alphabet = Alphabet::A1;
                    }
                }
                NOPRINT_CHAR
            }
            SHIFT_LOCK_DOWN => {
                match self.alphabet {
                    Alphabet::A0 => {
                        self.alphabet = Alphabet::A2;
                    }
                    Alphabet::A1 => {
                        self.alphabet = Alphabet::A0;
                    }
                    Alphabet::A2 => {
                        self.alphabet = Alphabet::A1;
                    }
                }
                self.next_alphabet = self.alphabet; // shift is permanent
                NOPRINT_CHAR
            }
            _ => match self.alphabet {
                Alphabet::A0 => {
                    self.alphabet = self.next_alphabet;
                    A0_CHARS[zc as usize]
                }
                Alphabet::A1 => {
                    self.alphabet = self.next_alphabet;
                    A1_CHARS[zc as usize]
                }
                Alphabet::A2 => {
                    self.alphabet = self.next_alphabet;
                    A2_CHARS[zc as usize]
                }
            },
        }
    }
}

// V3 mapper
pub struct ZCharacterMapperV3 {
    alphabet: Alphabet,
    preserved: Alphabet,
}

impl ZCharacterMapperV3 {
    pub fn create() -> ZCharacterMapperV3 {
        ZCharacterMapperV3 {
            alphabet: Alphabet::A0,
            preserved: Alphabet::A0,
        }
    }
}

impl ZCharacterMapper for ZCharacterMapperV3 {
    fn reset(&mut self) {
        self.alphabet = Alphabet::A0;
    }

    fn preserve_state(&mut self) {
        self.preserved = self.alphabet;
    }

    fn restore_state(&mut self) {
        self.alphabet = self.preserved;
    }

    ///
    /// Maps a zcharacter onto an intermediate character for processing into text
    ///
    fn map(&mut self, zc: u8) -> u8 {
        if zc > 31 {
            return NOPRINT_CHAR;
        }

        if zc == ABBREV_1 || zc == ABBREV_2 || zc == ABBREV_3 {
            return zc;
        }

        // Note that in V3 the shift locks are single shifts. The
        // single shift characters are used for abbreviations
        if zc == SHIFT_LOCK_UP {
            self.alphabet = Alphabet::A1;
            return NOPRINT_CHAR;
        }

        if zc == SHIFT_LOCK_DOWN {
            self.alphabet = Alphabet::A2;
            return NOPRINT_CHAR;
        }

        match self.alphabet {
            Alphabet::A0 => A0_CHARS[zc as usize],
            Alphabet::A1 => {
                self.alphabet = Alphabet::A0;
                A1_CHARS[zc as usize]
            }
            Alphabet::A2 => {
                self.alphabet = Alphabet::A0;
                A2_CHARS[zc as usize]
            }
        }
    }
}
