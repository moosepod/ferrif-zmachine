! Simple inform program with some objects
! Must compile with -e for abbreviations to be used
! inform -v3 -e basic_2.story

! Use all the attributes helps to test they are read correctly
Attribute test_1;
Attribute test_2;
Attribute test_3;
Attribute test_4;
Attribute test_5;
Attribute test_6;
Attribute test_7;
Attribute test_8;
Attribute test_9;
Attribute test_10;
Attribute test_11;
Attribute test_12;
Attribute test_13;
Attribute test_14;
Attribute test_15;
Attribute test_16;
Attribute test_17;
Attribute test_18;
Attribute test_19;
Attribute test_20;
Attribute test_21;
Attribute test_22;
Attribute test_23;
Attribute test_24;
Attribute test_25;
Attribute test_26;
Attribute test_27;
Attribute test_28;
Attribute test_29;
Attribute test_30;
Attribute test_31;
Attribute test_32;

Abbreviate " Test ";

Object TestParent "A Test Parent";

Object -> TestChild "A Test Child"
with description "This is a test",
name "a" "b" "c"
has test_8 test_16 test_24 test_32;

! The [X] tests non-unicode but still extended chars
Object -> TestSibling "A Test Sib [X] ling"
with b 5
has test_1 test_2 test_3 test_4 test_5 test_6 test_7 test_8 test_9 test_10 test_11 test_12 test_13 test_14 test_15 test_16 test_17 test_18 test_19 test_20 test_21 test_22 test_23 test_24 test_25 test_26 test_27 test_28 test_29 test_30 test_31 test_32
;

Object -> TextTest "Aa Bb^Cc0Dd1Ee2Ff3Gg4Hh5Ii6Jj7Kk8Ll9Mm.Nn,Oo!Pp?Qq_Rr#Ss'Tt~Uu/Vv@@92Ww-Xx:Yy(Zz)";
! Corresponds to "äöüÄÖÜß»«ëïÿËÏáéíóúýÁÉÍÓÚÝàèìòùÀÈÌÒÙâêîôûÂÊÎÔÛåÅøØãñõÃÑÕæÆçÇþðÞÐ£œŒ¡¿";
Object -> TestUnicode "@@155@@156@@157@@158@@159@@160@@161@@162@@163@@164@@165@@166@@167@@168@@169@@170@@171@@172@@173@@174@@175@@176@@177@@178@@179@@180@@181@@182@@183@@184@@185@@186@@187@@188@@189@@190@@191@@192@@193@@194@@195@@196@@197@@198@@199@@200@@201@@202@@203@@204@@205@@206@@207@@208@@209@@210@@211@@212@@213@@214@@215@@216@@217@@218@@219@@220@@221@@222@@223";

! Test object with empty name
Object -> TestEmpty "";

[Main ;
print "Hello world^";
];
