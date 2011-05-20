with SHA_3.JH;

package body JH_Tests is
   use SHA_3;
   procedure Initialize (T : in out Test) is
   begin
      Set_Name (T, "JH Tests");
      Ahven.Framework.Add_Test_Routine
        (T, Test_224_Bits_1'Access, "224 Bit Hash, 1 Block");
      Ahven.Framework.Add_Test_Routine
        (T, Test_224_Bits_2'Access, "224 Bit Hash, 2 Block");
      Ahven.Framework.Add_Test_Routine
        (T, Test_256_Bits_1'Access, "256 Bit Hash, 1 Block");
      Ahven.Framework.Add_Test_Routine
        (T, Test_256_Bits_2'Access, "256 Bit Hash, 2 Block");
      Ahven.Framework.Add_Test_Routine
        (T, Test_384_Bits_1'Access, "384 Bit Hash, 1 Block");
      Ahven.Framework.Add_Test_Routine
        (T, Test_384_Bits_2'Access, "384 Bit Hash, 2 Block");
      Ahven.Framework.Add_Test_Routine
        (T, Test_512_Bits_1'Access, "512 Bit Hash, 1 Block");
      Ahven.Framework.Add_Test_Routine
        (T, Test_512_Bits_2'Access, "512 Bit Hash, 2 Block");
   end Initialize;

   subtype Hash_224 is Bit_Sequence (0 .. 224 / 8 - 1);
   procedure Assert_Hash_224_Equals is new Ahven.Assert_Equal
     (Data_Type => Hash_224,
      Image     => Bit_Sequence_To_Hex_String);

   procedure Test_224_Bits_1 is
      Input    : constant Bit_Sequence (0 .. 0) := (0 => 0);
      Expected : constant Hash_224 :=
        Hex_String_To_Bit_Sequence
          ("88F4DCE7C6221151432031CBC4A109C350BE601D388D2D20F3AF6342");
      Result   : Hash_224;
   begin
      JH.Hash (Hash_Length => 224,
                  Input => Input,
                  Bit_Count => U64 (Input'Length) * 8,
                  Output      => Result);
      Assert_Hash_224_Equals (Actual   => Result,
                              Expected => Expected,
                              Message  => "Hash differs!");
   end Test_224_Bits_1;

   procedure Test_224_Bits_2 is
      Input    : constant String :=
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
      Expected : constant Hash_224 :=
        Hex_String_To_Bit_Sequence
          ("b7b310994ad64eb635141fce7a8494703da7db05099a89fdd004c940");
      Result   : Hash_224;
   begin
      JH.Hash (Hash_Length => 224,
                  Input => String_To_Bit_Sequence (Input),
                  Bit_Count => U64 (Input'Length) * 8,
                  Output => Result);
      Assert_Hash_224_Equals (Actual   => Result,
                              Expected => Expected,
                              Message  => "Hash differs!");
   end Test_224_Bits_2;

   subtype Hash_256 is Bit_Sequence (0 .. 256 / 8 - 1);
   procedure Assert_Hash_256_Equals is new Ahven.Assert_Equal
     (Data_Type => Hash_256,
      Image     => Bit_Sequence_To_Hex_String);

   procedure Test_256_Bits_1 is
      Input    : constant Bit_Sequence (0 .. 0) := (0 => 0);
      Expected : constant Hash_256 :=
        Hex_String_To_Bit_Sequence
          ("649D408B5ABF79906A84EBD5DC8166C57113575C250501B8E98C9EF5FC586347");
      Result   : Hash_256;
   begin
      JH.Hash (Hash_Length => 256,
                  Input => Input,
                  Bit_Count => U64 (Input'Length) * 8,
                  Output => Result);
      Assert_Hash_256_Equals (Actual   => Result,
                              Expected => Expected,
                              Message  => "Hash differs!");
   end Test_256_Bits_1;

   procedure Test_256_Bits_2 is
      Input    : constant String :=
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
      Expected : constant Hash_256 :=
        Hex_String_To_Bit_Sequence
          ("22c23b160e561f80924d44f2cc5974cd5a1d36f69324211861e63b9b6cb7974c");
      Result   : Hash_256;
   begin
      JH.Hash (Hash_Length => 256,
                  Input => String_To_Bit_Sequence (Input),
                  Bit_Count => U64 (Input'Length) * 8,
                  Output => Result);
      Assert_Hash_256_Equals (Actual   => Result,
                              Expected => Expected,
                              Message  => "Hash differs!");
   end Test_256_Bits_2;

   subtype Hash_384 is Bit_Sequence (0 .. 384 / 8 - 1);
   procedure Assert_Hash_384_Equals is new Ahven.Assert_Equal
     (Data_Type => Hash_384,
      Image     => Bit_Sequence_To_Hex_String);

   procedure Test_384_Bits_1 is
      Input    : constant Bit_Sequence (0 .. 0) := (0 => 0);
      Expected : constant Hash_384 :=
        Hex_String_To_Bit_Sequence
          ("3CDD9CCED9655CF4942C62DD03370186D890156A2AB54BCBFC91F4CA1C84A5F1901164A4B3FEA90F762BBA6483A8A093");
      Result   : Hash_384;
   begin
      JH.Hash (Hash_Length => 384,
                  Input => Input,
                  Bit_Count => U64 (Input'Length) * 8,
                  Output => Result);
      Assert_Hash_384_Equals (Actual   => Result,
                              Expected => Expected,
                              Message  => "Hash differs!");
   end Test_384_Bits_1;

   procedure Test_384_Bits_2 is
      Input    : constant String :=
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqopqrpqrsqrstrstustuvtuvwuvwxvwxywxyzxyzayzabzabcabcdbcdecdefdefg";
      Expected : constant Hash_384 :=
        Hex_String_To_Bit_Sequence
          ("33625fdddcc2809a83b912d70910d3b5e1408ef017c949617c5543bb835939f13484e60bfe6ff27acf225c7a4b596504");
      Result   : Hash_384;
   begin
      JH.Hash (Hash_Length => 384,
                  Input => String_To_Bit_Sequence (Input),
                  Bit_Count => U64 (Input'Length) * 8,
                  Output => Result);
      Assert_Hash_384_Equals (Actual   => Result,
                              Expected => Expected,
                              Message  => "Hash differs!");
   end Test_384_Bits_2;

   subtype Hash_512 is Bit_Sequence (0 .. 512 / 8 - 1);
   procedure Assert_Hash_512_Equals is new Ahven.Assert_Equal
     (Data_Type => Hash_512,
      Image     => Bit_Sequence_To_Hex_String);

   procedure Test_512_Bits_1 is
      Input    : constant Bit_Sequence (0 .. 0) := (0 => 0);
      Expected : constant Hash_512 :=
        Hex_String_To_Bit_Sequence
          ("0C6CC1FE8EDF03AD639CBBE90F796A4F9BF196EAC21D3C9F1E44FC02F60D6F51" &
           "6A0C3A5BF636223C9AFB2EF49DDCCCBE2431E965B413088712E2F40662EB466E");
      Result   : Hash_512;
   begin
      JH.Hash (Hash_Length => 512,
                  Input => Input,
                  Bit_Count => U64 (Input'Length) * 8,
                  Output => Result);
      Assert_Hash_512_Equals (Actual   => Result,
                              Expected => Expected,
                              Message  => "Hash differs!");
   end Test_512_Bits_1;

   procedure Test_512_Bits_2 is
      Input    : constant String :=
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqopqrpqrsqrstrstustuvtuvwuvwxvwxywxyzxyzayzabzabcabcdbcdecdefdefg";
      Expected : constant Hash_512 :=
        Hex_String_To_Bit_Sequence
          ("9f0867f941b5f3f2520e7b60b6e615eca82b61e2c5dd810f562450466f6a80fd72e6391f829dea656c4f84cdd7615e2098a99336d330b7226299e4139d3def75");
      Result   : Hash_512;
   begin
      JH.Hash (Hash_Length => 512,
                  Input => String_To_Bit_Sequence (Input),
                  Bit_Count => U64 (Input'Length) * 8,
                  Output => Result);
      Assert_Hash_512_Equals (Actual   => Result,
                              Expected => Expected,
                              Message  => "Hash differs!");
   end Test_512_Bits_2;

end JH_Tests;
