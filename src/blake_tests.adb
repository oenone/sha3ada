with SHA_3.BLAKE;

package body BLAKE_Tests is
   use SHA_3;
   procedure Initialize (T : in out Test) is
   begin
      Set_Name (T, "BLAKE Tests");
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
          ("4504CB0314FB2A4F7A692E696E487912FE3F2468FE312C73A5278EC5");
      Result   : Hash_224;
   begin
      BLAKE.Hash (Hash_Length => 224,
                  Input => Input,
                  Bit_Count => U64 (Input'Length) * 8,
                  Output      => Result);
      Assert_Hash_224_Equals (Actual   => Result,
                              Expected => Expected,
                              Message  => "Hash differs!");
   end Test_224_Bits_1;

   procedure Test_224_Bits_2 is
      Input    : constant Bit_Sequence (0 .. 576 / 8 - 1) := (others => 0);
      Expected : constant Hash_224 :=
        Hex_String_To_Bit_Sequence
          ("F5AA00DD1CB847E3140372AF7B5C46B4888D82C8C0A917913CFB5D04");
      Result   : Hash_224;
   begin
      BLAKE.Hash (Hash_Length => 224,
                  Input => Input,
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
      Input    : constant Bit_Sequence (0 .. 0) := (others => 0);
      Expected : constant Hash_256 :=
        Hex_String_To_Bit_Sequence
          ("0CE8D4EF4DD7CD8D62DFDED9D4EDB0A774AE6A41929A74DA23109E8F11139C87");
      Result   : Hash_256;
   begin
      BLAKE.Hash (Hash_Length => 256,
                  Input => Input,
                  Bit_Count => U64 (Input'Length) * 8,
                  Output => Result);
      Assert_Hash_256_Equals (Actual   => Result,
                              Expected => Expected,
                              Message  => "Hash differs!");
   end Test_256_Bits_1;

   procedure Test_256_Bits_2 is
      Input    : constant Bit_Sequence (0 .. 576 / 8 - 1) := (others => 0);
      Expected : constant Hash_256 :=
        Hex_String_To_Bit_Sequence
          ("D419BAD32D504FB7D44D460C42C5593FE544FA4C135DEC31E21BD9ABDCC22D41");
      Result   : Hash_256;
   begin
      BLAKE.Hash (Hash_Length => 256,
                  Input => Input,
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
      Input    : constant Bit_Sequence (0 .. 0) := (others => 0);
      Expected : constant Hash_384 :=
        Hex_String_To_Bit_Sequence
          ("10281F67E135E90AE8E882251A355510A719367AD70227B137343E1BC122015C" &
           "29391E8545B5272D13A7C2879DA3D807");
      Result   : Hash_384;
   begin
      BLAKE.Hash (Hash_Length => 384,
                  Input => Input,
                  Bit_Count => U64 (Input'Length) * 8,
                  Output => Result);
      Assert_Hash_384_Equals (Actual   => Result,
                              Expected => Expected,
                              Message  => "Hash differs!");
   end Test_384_Bits_1;

   procedure Test_384_Bits_2 is
      Input    : constant Bit_Sequence (0 .. 1152 / 8 - 1) := (others => 0);
      Expected : constant Hash_384 :=
        Hex_String_To_Bit_Sequence
          ("0B9845DD429566CDAB772BA195D271EFFE2D0211F16991D766BA749447C5CDE5" &
           "69780B2DAA66C4B224A2EC2E5D09174C");
      Result   : Hash_384;
   begin
      BLAKE.Hash (Hash_Length => 384,
                  Input => Input,
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
      Input    : constant Bit_Sequence (0 .. 0) := (others => 0);
      Expected : constant Hash_512 :=
        Hex_String_To_Bit_Sequence
          ("97961587F6D970FABA6D2478045DE6D1FABD09B61AE50932054D52BC29D31BE4" &
           "FF9102B9F69E2BBDB83BE13D4B9C06091E5FA0B48BD081B634058BE0EC49BEB3");
      Result   : Hash_512;
   begin
      BLAKE.Hash (Hash_Length => 512,
                  Input => Input,
                  Bit_Count => U64 (Input'Length) * 8,
                  Output => Result);
      Assert_Hash_512_Equals (Actual   => Result,
                              Expected => Expected,
                              Message  => "Hash differs!");
   end Test_512_Bits_1;

   procedure Test_512_Bits_2 is
      Input    : constant Bit_Sequence (0 .. 1152 / 8 - 1) := (others => 0);
      Expected : constant Hash_512 :=
        Hex_String_To_Bit_Sequence
          ("313717D608E9CF758DCB1EB0F0C3CF9FC150B2D500FB33F51C52AFC99D358A2F" &
           "1374B8A38BBA7974E7F6EF79CAB16F22CE1E649D6E01AD9589C213045D545DDE");
      Result   : Hash_512;
   begin
      BLAKE.Hash (Hash_Length => 512,
                  Input => Input,
                  Bit_Count => U64 (Input'Length) * 8,
                  Output => Result);
      Assert_Hash_512_Equals (Actual   => Result,
                              Expected => Expected,
                              Message  => "Hash differs!");
   end Test_512_Bits_2;

end BLAKE_Tests;
