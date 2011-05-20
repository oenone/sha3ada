package SHA_3.BLAKE is
   type BLAKE_State is new Hash_State with private;

   procedure Init (Hash : in out BLAKE_State; Hash_Length : Positive);
   procedure Add_Salt (Hash : in out BLAKE_State; Salt : Bit_Sequence);
   procedure Update
     (Hash      : in out BLAKE_State;
      Input     : Bit_Sequence;
      Bit_Count : Data_Length_Type);
   procedure Final (Hash : in out BLAKE_State; Output : out Bit_Sequence);

   procedure Hash
     (Hash_Length : Positive;
      Input       : Bit_Sequence;
      Bit_Count   : Data_Length_Type;
      Output      : out Bit_Sequence);

private
   Rounds_32 : constant := 14;
   Rounds_64 : constant := 16;

   type BLAKE_State is new Hash_State with record
      Hash_Length : Positive;
      Data_Length : Data_Length_Type;
      Initialized : Boolean;
      Null_T      : Boolean;
      -- 32 bit version
      H32         : U32_Array (0 .. 7); -- current chain value (initialized by the IV)
      T32         : U32_Array (0 .. 1); -- number of bits hashed so far
      Data32      : Bit_Sequence (0 .. 63); -- remaining data to hash (less than a block)
      Salt32      : U32_Array (0 .. 3); -- salt (null by default)
      -- 64 bit version
      H64         : U64_Array (0 .. 7); -- current chain value (initialized by the IV)
      T64         : U64_Array (0 .. 1); -- number of bits hashed so far
      Data64      : Bit_Sequence (0 .. 127); -- remaining data to hash (less than a block)
      Salt64      : U64_Array (0 .. 3); -- salt (null by default)
   end record;

end SHA_3.BLAKE;
