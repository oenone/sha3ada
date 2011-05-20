package SHA_3.JH is

   type JH_State is new Hash_State with private;

   procedure Init (Hash : in out JH_State; Hash_Length : Positive);
   procedure Update
     (Hash      : in out JH_State;
      Input     : Bit_Sequence;
      Bit_Count : Data_Length_Type);
   procedure Final (Hash : in out JH_State; Output : out Bit_Sequence);

   procedure Hash
     (Hash_Length : Positive;
      Input       : Bit_Sequence;
      Bit_Count   : Data_Length_Type;
      Output      : out Bit_Sequence);

private

   type JH_State is new Hash_State with record
      -- message digest size
      Hash_Length    : Natural;
      -- message size in bits
      Data_Length    : Data_Length_Type;
      -- message remaining in buffer
      Buffer_Length  : Natural;
      -- Hash value H, 128 Bytes
      H              : U8_Array (0 .. 127);
      -- temporary round value, 256 4-bit elements
      A              : U4_Array (0 .. 255);
      -- round constant for one round, 64 4-bit elements
      Round_Constant : U4_Array (0 .. 63);
      -- message block to be hashed, 64 bytes
      Buffer         : U8_Array (0 .. 63);
   end record;

end SHA_3.JH;
