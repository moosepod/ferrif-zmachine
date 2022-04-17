! Stub program used for building and testing rustterp
! Input routines from https://www.inform-fiction.org/manual/html/s2.html#s2_5

Array text_array -> 63;
Array parse_array -> 42;


[ Main;
    print "Please enter some text^> ";
    text_array->0 = 60; 
    parse_array->0 = 10;
    read text_array parse_array;    
    print "The first character you typed was ",text_array->1,"^";

    ! Test some math instructions
    print "^Testing ADD^";
    print "5 + ",text_array->1," = ",5 + text_array->1,"^";
    print "500000 + ",text_array->1," = ",500000 + text_array->1,"^"; ! test overflow
    print "-5 + ",text_array->1," = ",-5 + text_array->1 ,"^";
    print "-500 + ",text_array->1," = ",-500 + text_array->1 ,"^";
    print "^Please enter ";
    ! Force some dictionary words to be defined
    print (address) 'some';
    print " ";
    print (address) 'more';
    print " ";
    print (address) 'text';
    print "^> ";

    text_array->0 = 60; 
    parse_array->0 = 10;
    read text_array parse_array;
    print "You entered ",parse_array->1," words.^";
    print "And now, we're done.^";

    quit;
];