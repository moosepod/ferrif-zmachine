! Stub program used for building and testing rustterp's screen library
! Input routines from https://www.inform-fiction.org/manual/html/s2.html#s2_5

! Adventure's IFID -- see http://babel.ifarchive.org/
Array UUID_ARRAY string "UUID://72a39f90-eb64-4d61-b9dd-f68032e22688//"; 
#Ifdef UUID_ARRAY; #Endif;


Array text_array -> 63;
Array parse_array -> 42;


[ Main;
    print "Version 1.13.^";
    print "This is the lower window.^";
    @set_window 0;
    @show_status;
    print "This is the lower window again.^";

    do {
        ! Force some dictionary words to be defined
        ! and validate word count
        print "^(U)pper window print (P) Upper print (L)ower window print clea(R) upper (O)pen upper (C)lose upper (Q)uit.";
        print "^> ";
        text_array->0 = 60; 
        parse_array->0 = 10;
        read text_array parse_array;
        if (text_array->1 == 117) {
            @set_window 1;
            print "Here is a line of text.^";
            @set_window 0;
        } else if (text_array->1 == 108) {
            @set_window 0;
            print "Here is a line of text.^";
        }else if (text_array->1 == 112) {
            @set_window 1;
            print "Line 1 of 6.^";
            print "Line 2 of 6.^";
            print "Line 3 of 6.^";
            print "Line 4 of 6.^";
            print "Line 5 of 6.^";
            print "Line 6 of 6.^";
            @set_window 0;
        }else if (text_array->1 == 114) {
            @set_window 1;
            print "                                        ^";
            print "                                        ^";
            print "                                        ^";
            print "                                        ^";
            print "                                        ^";
            print "                                        ^";
            @set_window 0;
        } else if (text_array->1 == 111) {
            @split_window 5;
            @set_window 1;
            print "Opened top window.";
            @set_window 0;
        } else if (text_array->1 == 99) {
            @split_window 0;
            print "Closed top window.";
        }
    } until (text_array->1 == 113);

    print "^And now, we're done.^";

    quit;
];
