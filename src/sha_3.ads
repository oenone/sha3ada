package SHA_3 is
   type U1 is mod 2 ** 1;
   type U1_Array is array (Natural range <>) of U1;
   type U4 is mod 2 ** 4;
   type U4_Array is array (Natural range <>) of U4;
   type U8 is mod 2 ** 8;
   type U8_Array is array (Natural range <>) of U8;
   type U16 is mod 2 ** 16;
   type U16_Array is array (Natural range <>) of U16;
   type U32 is mod 2 ** 32;
   type U32_Array is array (Natural range <>) of U32;
   type U64 is mod 2 ** 64;
   type U64_Array is array (Natural range <>) of U64;

   -- conversion to/from byte-arrays
   function U8_To_U32 (From : U8_Array) return U32;
   function U8_To_U64 (From : U8_Array) return U64;
   function U32_To_U8 (From : U32) return U8_Array;
   function U64_To_U8 (From : U64) return U8_Array;

   -- conversion to/from hexadecimal string representation
   function Hex_To_U8 (S : String) return U8;
   subtype U8_String is String (1 .. 2);
   function U8_To_Hex (X : U8) return U8_String;

   subtype Bit_Sequence is U8_Array;
   subtype Data_Length_Type is U64;

   -- conversion to/from string
   function String_To_Bit_Sequence (S : String) return Bit_Sequence;
   function Hex_String_To_Bit_Sequence (S : String) return Bit_Sequence;
   function Bit_Sequence_To_String (B : Bit_Sequence) return String;
   function Bit_Sequence_To_Hex_String (B : Bit_Sequence) return String;

   type Hash_State is abstract tagged private;

   procedure Init
     (Hash        : in out Hash_State;
      Hash_Length : Positive) is abstract;
   procedure Update
     (Hash      : in out Hash_State;
      Input     : Bit_Sequence;
      Bit_Count : Data_Length_Type) is abstract;
   procedure Final
     (Hash   : in out Hash_State;
      Output : out Bit_Sequence) is abstract;

   procedure Hash
     (Hash_Length : Positive;
      Input       : Bit_Sequence;
      Bit_Count   : Data_Length_Type;
      Output      : out Bit_Sequence)
   is null;

   FAIL : exception;
   BAD_HASH_LENGTH : exception;
private

   type Hash_State is abstract tagged null record;

end SHA_3;
