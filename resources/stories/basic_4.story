! Stub program used for building and testing rustterp
! Input routines from https://www.inform-fiction.org/manual/html/s2.html#s2_5

Array text_array -> 63;
Array parse_array -> 42;
Array memory_stream1 -> 100;
Array memory_stream2 -> 100;


[ Main;
    ! Test a handful of opcodes not tested by czech
    @store 16 5; ! test object
    @store 17 11; ! score
    @split_window 5;
    @set_window 1;
    print "This is the upper window.^Five lines total.";
    @set_window 0;
    @show_status;
    print "Activating FILE stream^";
    @input_stream 1;
    print "Activating KEYBOARD stream^";
    @input_stream 0;
    
    print "Deactivating then activating SCREEN stream^";
    @output_stream -1 0;
    @output_stream 1 0;
    print "Activating TRANSCRIPT stream^";
    @output_stream 2 0;
    print "Activating, printing, then deactivating MEMORY streams. Should not see message 'Memory stream' in subsequent lines^";
    @output_stream 3 memory_stream1;
    print "Memory ";
    @output_stream 3 memory_stream2;
    print "Another memory stream";
    @output_stream -3 memory_stream1;
    print "stream";
    @output_stream -3 memory_stream2;
    print "First table contains ";
    print memory_stream1->1;
    print " characters, first character is ";
    print memory_stream1->2;
    print ". Expected 13, 77.^";
    print "Second table contains ";
    print memory_stream2->1;
    print " characters, first character is ";
    print memory_stream2->2;
    print ". Expected 21, 65.^";    
    print "Activating COMMAND stream^";
    @output_stream 4 0;
    print "Setting output stream 0, does nothing^";
    @output_stream 0 0;
    print "Playing sound effect (low beep)^";
    @sound_effect 1;
    print "Playing sound effect (high beep)^";
    @sound_effect 2;
    print "Playing sound effect (other sound)^";
    @sound_effect 3 1 2;
    
    do {
        ! Force some dictionary words to be defined
        ! and validate word count
        print "^Please enter ";
        print (address) 'some';
        print " ";
        print (address) 'text';
        print ". Should not allow more than 20 characters to be typed.^> ";
        text_array->0 = 20; 
        parse_array->0 = 10;
        read text_array parse_array;
    } until (CheckText(text_array->1,parse_array->1) > 120);

    @output_stream -4 0;
    @output_stream -2 0;
    print "^Command and transcript screens deactivated";
    print "^And now, we're done.^";

    quit;
];

[ CheckText typedChar wordCount; 
        print "You entered ",wordCount," words.^";
        print "The first character you typed was ",typedChar,"^";

        if (typedChar < 110) {
            print "It is less than 110.^";
        }

        if (typedChar > 100) {
            print "It is greater than than 100.^";
        }

        ! Test some math instructions
        print "^Testing ADD^";
        print "5 + ",typedChar," = ",5 + typedChar,"^";
        print "500000 + ",typedChar," = ",500000 + typedChar,"^"; ! test overflow
        print "-5 + ",typedChar," = ",-5 + typedChar ,"^";
        print "-500 + ",typedChar," = ",-500 + typedChar ,"^";

        print "^Testing SUB^";
        print "5 - ",typedChar," = ",5 - typedChar,"^";
        print "500000 - ",typedChar," = ",500000 - typedChar,"^"; ! test overflow
        print "200 - ",typedChar," = ",200 - typedChar ,"^";
        print "-500 - ",typedChar," = ",-500 - typedChar ,"^";

        print "^Testing MUL^";
        print "5 * ",typedChar," = ",5 * typedChar,"^";
        print "500000 * ",typedChar," = ",500000 * typedChar,"^"; ! test overflow
        print "-5 * ",typedChar," = ",-5 * typedChar ,"^";
        print "-500 * ",typedChar," = ",-500 * typedChar ,"^";

        print "^Testing DIV^";
        print "5 / ",typedChar," = ",5 / typedChar,"^";
        print "500000 / ",typedChar," = ",500000 / typedChar,"^"; ! test overflow
        print "-5 / ",typedChar," = ",-5 / typedChar ,"^";
        print "-500 / ",typedChar," = ",-500 / typedChar ,"^";

        print "^Testing MOD^";
        print "5 % ",typedChar," = ",5 % typedChar,"^";
        print "500000 % ",typedChar," = ",500000 % typedChar,"^"; ! test overflow
        print "-5 % ",typedChar," = ",-5 % typedChar ,"^";
        print "-500 % ",typedChar," = ",-500 % typedChar ,"^";

        print "^Testing AND and OR^";
        print "0x00ff & ",typedChar," = ", 255 & typedChar,"^";
        print "0x00ff | ",typedChar," = ", 255 | typedChar,"^";
        print "0x0000 & ",typedChar," = ", 0 & typedChar,"^";
        print "0x0000 | ",typedChar," = ", 0 | typedChar,"^";
        print "0x0003 & ",typedChar," = ", 3 & typedChar,"^";
        print "0x0003 | ",typedChar," = ", 3 | typedChar,"^";

        print "^Testing INC and DEC^";    
        print "testGlobal = ",typedChar,"^";
        print "typedChar++ = ";
        typedChar++;
        print typedChar,"^";    
        print "typedChar-- = ";
        typedChar--;
        print typedChar,"^";    
        print "typedChar-- = ";
        typedChar--;
        print typedChar,"^";  

        return typedChar;  
];

Object TestObject "A Test Object";
