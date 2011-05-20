package SHA_3.Groestl is
   type Groestl_State is new Hash_State with private;

   procedure Init (Hash : in out Groestl_State; Hash_Length : Positive);
   procedure Update
     (Hash      : in out Groestl_State;
      Input     : Bit_Sequence;
      Bit_Count : Data_Length_Type);
   procedure Final (Hash : in out Groestl_State; Output : out Bit_Sequence);

   procedure Hash
     (Hash_Length : Positive;
      Input       : Bit_Sequence;
      Bit_Count   : Data_Length_Type;
      Output      : out Bit_Sequence);

private
   ROWS              : constant := 8;
   LENGTHFIELDLENGTH : constant := ROWS;
   COLS512           : constant := 8;
   COLS1024          : constant := 16;
   SIZE512           : constant := ROWS * COLS512;
   SIZE1024          : constant := ROWS * COLS1024;
   ROUNDS512         : constant := 10;
   ROUNDS1024        : constant := 14;

   type Variant is (P512, Q512, P1024, Q1024);

   type U8_Array_2D is array (Natural range <>, Natural range <>) of U8;

   type Groestl_State is new Hash_State with record
      Chaining          : U8_Array_2D (0 .. ROWS - 1, 0 .. COLS1024 - 1);
      Block_Counter     : U64;
      Hash_Length       : Positive;
      Buffer            : Bit_Sequence (0 .. SIZE1024 - 1);
      Buffer_Index      : Natural;
      Bits_In_Last_Byte : Natural;
      Columns           : Natural;
      Rounds            : Natural;
      State_Size        : Natural;
   end record;

end SHA_3.Groestl;
