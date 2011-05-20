package body SHA_3.BLAKE is

   -- the 10 permutations of 0..15
   Sigma : constant array (0 .. 9, 0 .. 15) of Natural :=
     ((  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ),
      ( 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ),
      ( 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ),
      (  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ),
      (  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ),
      (  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ),
      ( 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ),
      ( 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ),
      (  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ),
      ( 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 ));

   -- constants for BLAKE-32 and BLAKE-28
   C32 : constant U32_Array (0 .. 15) :=
     (16#243F6A88#, 16#85A308D3#,
      16#13198A2E#, 16#03707344#,
      16#A4093822#, 16#299F31D0#,
      16#082EFA98#, 16#EC4E6C89#,
      16#452821E6#, 16#38D01377#,
      16#BE5466CF#, 16#34E90C6C#,
      16#C0AC29B7#, 16#C97C50DD#,
      16#3F84D5B5#, 16#B5470917#);

   -- constants for BLAKE-64 and BLAKE-48
   C64 : constant U64_Array (0 .. 15) :=
     (16#243F6A8885A308D3#, 16#13198A2E03707344#,
      16#A4093822299F31D0#, 16#082EFA98EC4E6C89#,
      16#452821E638D01377#, 16#BE5466CF34E90C6C#,
      16#C0AC29B7C97C50DD#, 16#3F84D5B5B5470917#,
      16#9216D5D98979FB1B#, 16#D1310BA698DFB5AC#,
      16#2FFD72DBD01ADFB7#, 16#B8E1AFED6A267E96#,
      16#BA7C9045F12C7F99#, 16#24A19947B3916CF7#,
      16#0801F2E2858EFC16#, 16#636920D871574E69#);

   -- padding data
   Padding : constant Bit_Sequence (0 .. 128) :=
     (16#80#,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

   -- initial values (IV-x for BLAKE-x)
   IV256 : constant U32_Array (0 .. 7) :=
     (16#6A09E667#, 16#BB67AE85#,
      16#3C6EF372#, 16#A54FF53A#,
      16#510E527F#, 16#9B05688C#,
      16#1F83D9AB#, 16#5BE0CD19#);
   IV224 : constant U32_Array (0 .. 7) :=
     (16#C1059ED8#, 16#367CD507#,
      16#3070DD17#, 16#F70E5939#,
      16#FFC00B31#, 16#68581511#,
      16#64F98FA7#, 16#BEFA4FA4#);
   IV384 : constant U64_Array (0 .. 7) :=
     (16#CBBB9D5DC1059ED8#, 16#629A292A367CD507#,
      16#9159015A3070DD17#, 16#152FECD8F70E5939#,
      16#67332667FFC00B31#, 16#8EB44A8768581511#,
      16#DB0C2E0D64F98FA7#, 16#47B5481DBEFA4FA4#);
   IV512 : constant U64_Array (0 .. 7) :=
     (16#6A09E667F3BCC908#, 16#BB67AE8584CAA73B#,
      16#3C6EF372FE94F82B#, 16#A54FF53A5F1D36F1#,
      16#510E527FADE682D1#, 16#9B05688C2B3E6C1F#,
      16#1F83D9ABFB41BD6B#, 16#5BE0CD19137E2179#);

   procedure Compress32 (Hash : in out BLAKE_State; Data_Block : Bit_Sequence) is
      function ROT32 (X : U32; N : Natural) return U32 is
      begin
         return X * 2 ** (32 - N) or X / 2 ** N;
      end ROT32;
      function ADD32 (X, Y : U32) return U32 is
      begin
         return X + Y;
      end ADD32;
      function XOR32 (X, Y : U32) return U32 is
      begin
         return X xor Y;
      end XOR32;
      V : U32_Array (0 .. 15);
      M : U32_Array (0 .. 15);
      procedure G32 (A, B, C, D, I, Round : Natural) is
      begin
         V (A) := ADD32 (V (A), V (B)) + XOR32 (M (Sigma (Round mod 10, 2 * I)), C32 (Sigma (Round mod 10, 2 * I + 1)));
         V (D) := ROT32 (XOR32 (V (D), V (A)), 16);
         V (C) := ADD32 (V (C), V (D));
         V (B) := ROT32 (XOR32 (V (B), V (C)), 12);
         V (A) := ADD32 (V (A), V (B)) + XOR32 (M (Sigma (Round mod 10, 2 * I + 1)), C32 (Sigma (Round mod 10, 2 * I)));
         V (D) := ROT32 (XOR32 (V (D), V (A)), 8);
         V (C) := ADD32 (V (C), V (D));
         V (B) := ROT32 (XOR32 (V (B), V (C)), 7);
      end G32;
   begin
      -- get message
      M (0) := U8_To_U32 (Data_Block (Data_Block'First + 0 .. Data_Block'First + 3));
      M (1) := U8_To_U32 (Data_Block (Data_Block'First + 4 .. Data_Block'First + 7));
      M (2) := U8_To_U32 (Data_Block (Data_Block'First + 8 .. Data_Block'First + 11));
      M (3) := U8_To_U32 (Data_Block (Data_Block'First + 12 .. Data_Block'First + 15));
      M (4) := U8_To_U32 (Data_Block (Data_Block'First + 16 .. Data_Block'First + 19));
      M (5) := U8_To_U32 (Data_Block (Data_Block'First + 20 .. Data_Block'First + 23));
      M (6) := U8_To_U32 (Data_Block (Data_Block'First + 24 .. Data_Block'First + 27));
      M (7) := U8_To_U32 (Data_Block (Data_Block'First + 28 .. Data_Block'First + 31));
      M (8) := U8_To_U32 (Data_Block (Data_Block'First + 32 .. Data_Block'First + 35));
      M (9) := U8_To_U32 (Data_Block (Data_Block'First + 36 .. Data_Block'First + 39));
      M (10) := U8_To_U32 (Data_Block (Data_Block'First + 40 .. Data_Block'First + 43));
      M (11) := U8_To_U32 (Data_Block (Data_Block'First + 44 .. Data_Block'First + 47));
      M (12) := U8_To_U32 (Data_Block (Data_Block'First + 48 .. Data_Block'First + 51));
      M (13) := U8_To_U32 (Data_Block (Data_Block'First + 52 .. Data_Block'First + 55));
      M (14) := U8_To_U32 (Data_Block (Data_Block'First + 56 .. Data_Block'First + 59));
      M (15) := U8_To_U32 (Data_Block (Data_Block'First + 60 .. Data_Block'First + 63));

      -- initialization
      V (0 .. 7) := Hash.H32;
      V (8) := Hash.Salt32(0) xor C32(0);
      V (9) := Hash.Salt32(1) xor C32(1);
      V (10) := Hash.Salt32(2) xor C32(2);
      V (11) := Hash.Salt32 (3) xor C32 (3);
      if Hash.Null_T then
         -- special case t=0 for the last block
         V (12) := C32 (4);
         V (13) := C32 (5);
         V (14) := C32 (6);
         V (15) := C32 (7);
      else
         V (12) := Hash.T32 (0) xor C32 (4);
         V (13) := Hash.T32 (0) xor C32 (5);
         V (14) := Hash.T32 (1) xor C32 (6);
         V (15) := Hash.T32 (1) xor C32 (7);
      end if;

      -- do 14 rounds
      for Round in 0 .. Rounds_32 - 1 loop

         -- column step
         G32 (0, 4, 8, 12, 0, Round);
         G32 (1, 5, 9, 13, 1, Round);
         G32 (2, 6, 10, 14, 2, Round);
         G32 (3, 7, 11, 15, 3, Round);

         -- diagonal step
         G32 (0, 5, 10, 15, 4, Round);
         G32 (1, 6, 11, 12, 5, Round);
         G32 (2, 7, 8, 13, 6, Round);
         G32 (3, 4, 9, 14, 7, Round);

      end loop;

      -- finalization
      Hash.H32 (0) := Hash.H32 (0) xor V (0) xor V (8) xor Hash.Salt32 (0);
      Hash.H32 (1) := Hash.H32 (1) xor V (1) xor V (9) xor Hash.Salt32 (1);
      Hash.H32 (2) := Hash.H32 (2) xor V (2) xor V (10) xor Hash.Salt32 (2);
      Hash.H32 (3) := Hash.H32 (3) xor V (3) xor V (11) xor Hash.Salt32 (3);
      Hash.H32 (4) := Hash.H32 (4) xor V (4) xor V (12) xor Hash.Salt32 (0);
      Hash.H32 (5) := Hash.H32 (5) xor V (5) xor V (13) xor Hash.Salt32 (1);
      Hash.H32 (6) := Hash.H32 (6) xor V (6) xor V (14) xor Hash.Salt32 (2);
      Hash.H32 (7) := Hash.H32 (7) xor V (7) xor V (15) xor Hash.Salt32 (3);
   end Compress32;

   procedure Compress64 (Hash : in out BLAKE_State; Data_Block : Bit_Sequence) is
      function ROT64 (X : U64; N : Natural) return U64 is
      begin
         return X * 2 ** (64 - N) or X / 2 ** N;
      end ROT64;
      function ADD64 (X, Y : U64) return U64 is
      begin
         return X + Y;
      end ADD64;
      function XOR64 (X, Y : U64) return U64 is
      begin
         return X xor Y;
      end XOR64;
      V : U64_Array (0 .. 15);
      M : U64_Array (0 .. 15);
      procedure G64 (A, B, C, D, I, Round : Natural) is
      begin
         V (A) := ADD64 (V (A), V (B)) + XOR64 (M (Sigma (Round mod 10, 2 * I)), C64 (Sigma (Round mod 10, 2 * I + 1)));
         V (D) := ROT64 (XOR64 (V (D), V (A)), 32);
         V (C) := ADD64 (V (C), V (D));
         V (B) := ROT64 (XOR64 (V (B), V (C)), 25);
         V (A) := ADD64 (V (A), V (B)) + XOR64 (M (Sigma (Round mod 10, 2 * I + 1)), C64 (Sigma (Round mod 10, 2 * I)));
         V (D) := ROT64 (XOR64 (V (D), V (A)), 16);
         V (C) := ADD64 (V (C), V (D));
         V (B) := ROT64 (XOR64 (V (B), V (C)), 11);
      end G64;
   begin
      -- get message
      M (0) := U8_To_U64 (Data_Block (Data_Block'First + 0 .. Data_Block'First + 7));
      M (1) := U8_To_U64 (Data_Block (Data_Block'First + 8 .. Data_Block'First + 15));
      M (2) := U8_To_U64 (Data_Block (Data_Block'First + 16 .. Data_Block'First + 23));
      M (3) := U8_To_U64 (Data_Block (Data_Block'First + 24 .. Data_Block'First + 31));
      M (4) := U8_To_U64 (Data_Block (Data_Block'First + 32 .. Data_Block'First + 39));
      M (5) := U8_To_U64 (Data_Block (Data_Block'First + 40 .. Data_Block'First + 47));
      M (6) := U8_To_U64 (Data_Block (Data_Block'First + 48 .. Data_Block'First + 55));
      M (7) := U8_To_U64 (Data_Block (Data_Block'First + 56 .. Data_Block'First + 63));
      M (8) := U8_To_U64 (Data_Block (Data_Block'First + 64 .. Data_Block'First + 71));
      M (9) := U8_To_U64 (Data_Block (Data_Block'First + 72 .. Data_Block'First + 79));
      M (10) := U8_To_U64 (Data_Block (Data_Block'First + 80 .. Data_Block'First + 87));
      M (11) := U8_To_U64 (Data_Block (Data_Block'First + 88 .. Data_Block'First + 95));
      M (12) := U8_To_U64 (Data_Block (Data_Block'First + 96 .. Data_Block'First + 103));
      M (13) := U8_To_U64 (Data_Block (Data_Block'First + 104 .. Data_Block'First + 111));
      M (14) := U8_To_U64 (Data_Block (Data_Block'First + 112 .. Data_Block'First + 119));
      M (15) := U8_To_U64 (Data_Block (Data_Block'First + 120 .. Data_Block'First + 127));

      -- initialization
      V (0 .. 7) := Hash.H64;
      V (8) := Hash.Salt64(0) xor C64(0);
      V (9) := Hash.Salt64(1) xor C64(1);
      V (10) := Hash.Salt64(2) xor C64(2);
      V (11) := Hash.Salt64 (3) xor C64 (3);
      if Hash.Null_T then
         -- special case t=0 for the last block
         V (12) := C64 (4);
         V (13) := C64 (5);
         V (14) := C64 (6);
         V (15) := C64 (7);
      else
         V (12) := Hash.T64 (0) xor C64 (4);
         V (13) := Hash.T64 (0) xor C64 (5);
         V (14) := Hash.T64 (1) xor C64 (6);
         V (15) := Hash.T64 (1) xor C64 (7);
      end if;

      -- do 16 rounds
      for Round in 0 .. Rounds_64 - 1 loop

         -- column step
         G64 (0, 4, 8, 12, 0, Round);
         G64 (1, 5, 9, 13, 1, Round);
         G64 (2, 6, 10, 14, 2, Round);
         G64 (3, 7, 11, 15, 3, Round);

         -- diagonal step
         G64 (0, 5, 10, 15, 4, Round);
         G64 (1, 6, 11, 12, 5, Round);
         G64 (2, 7, 8, 13, 6, Round);
         G64 (3, 4, 9, 14, 7, Round);

      end loop;

      -- finalization
      Hash.H64 (0) := Hash.H64 (0) xor V (0) xor V (8) xor Hash.Salt64 (0);
      Hash.H64 (1) := Hash.H64 (1) xor V (1) xor V (9) xor Hash.Salt64 (1);
      Hash.H64 (2) := Hash.H64 (2) xor V (2) xor V (10) xor Hash.Salt64 (2);
      Hash.H64 (3) := Hash.H64 (3) xor V (3) xor V (11) xor Hash.Salt64 (3);
      Hash.H64 (4) := Hash.H64 (4) xor V (4) xor V (12) xor Hash.Salt64 (0);
      Hash.H64 (5) := Hash.H64 (5) xor V (5) xor V (13) xor Hash.Salt64 (1);
      Hash.H64 (6) := Hash.H64 (6) xor V (6) xor V (14) xor Hash.Salt64 (2);
      Hash.H64 (7) := Hash.H64 (7) xor V (7) xor V (15) xor Hash.Salt64 (3);
   end Compress64;

   procedure Init (Hash : in out BLAKE_State; Hash_Length : Positive) is
   begin
      if Hash_Length = 224 or else Hash_Length = 256 then
         -- 224- and 256-bit versions (32-bit words)
         if Hash_Length = 224 then
            Hash.H32 := IV224;
         else
            Hash.H32 := IV256;
         end if;

         Hash.T32 := (others => 0);

         Hash.Data32 := (others => 0);
         Hash.Salt32 := (others => 0);
      elsif Hash_Length = 384 or else Hash_Length = 512 then
         if Hash_Length = 384 then
            Hash.H64 := IV384;
         else
            Hash.H64 := IV512;
         end if;

         Hash.T64 := (others => 0);

         Hash.Data64 := (others => 0);
         Hash.Salt64 := (others => 0);
      else
         raise BAD_HASH_LENGTH;
      end if;

      Hash.Hash_Length := Hash_Length;
      Hash.Data_Length := 0;
      Hash.Initialized := True;
      Hash.Null_T := False;
   end Init;

   procedure Add_Salt (Hash : in out BLAKE_State; Salt : Bit_Sequence) is
   begin
      -- if hashbitlen=224 or 256, then the salt should be 128-bit (16 bytes)
      -- if hashbitlen=384 or 512, then the salt should be 256-bit (32 bytes)

      -- fail if Init() was not called before
      if not Hash.Initialized then
         raise FAIL;
      end if;

      if Hash.Hash_Length < 384 then
         if Salt'Length /= 16 then
            raise Constraint_Error;
         end if;
         Hash.Salt32 (0) := U8_To_U32 (Salt (Salt'First + 0 .. Salt'First + 3));
         Hash.Salt32 (1) := U8_To_U32 (Salt (Salt'First + 4 .. Salt'First + 7));
         Hash.Salt32 (2) := U8_To_U32 (Salt (Salt'First + 8 .. Salt'First + 11));
         Hash.Salt32 (3) := U8_To_U32 (Salt (Salt'First + 12 .. Salt'First + 15));
      else
         if Salt'Length /= 32 then
            raise Constraint_Error;
         end if;
         Hash.Salt64 (0) := U8_To_U64 (Salt (Salt'First + 0 .. Salt'First + 7));
         Hash.Salt64 (1) := U8_To_U64 (Salt (Salt'First + 8 .. Salt'First + 15));
         Hash.Salt64 (2) := U8_To_U64 (Salt (Salt'First + 16 .. Salt'First + 23));
         Hash.Salt64 (3) := U8_To_U64 (Salt (Salt'First + 24 .. Salt'First + 31));
      end if;
   end Add_Salt;

   procedure Update32 (Hash : in out BLAKE_State; Data : Bit_Sequence; Data_Length : Data_Length_Type) is
      Fill : Natural;
      Left : Natural; -- to handle data inputs of up to 2^64-1 bits
      Data_Index : Natural := Data'First;
      Length : Data_Length_Type := Data_Length;
   begin
      if Length = 0 and then Hash.Data_Length /= 512 then
         return;
      end if;

      Left := Natural (Hash.Data_Length / 8);
      Fill := 64 - Left;

      -- compress remaining data filled with new bits
      if Left > 0 and then Natural (Length / 8) mod 64 >= Fill then
         Hash.Data32 (Hash.Data32'First + Left .. Hash.Data32'First + Left + Fill - 1) :=
           Data (Data_Index .. Data_Index + Fill - 1);
         -- update counter
         Hash.T32 (0) := Hash.T32 (0) + 512;
         if Hash.T32 (0) = 0 then
            Hash.T32 (1) := Hash.T32 (1) + 1;
         end if;

         Compress32 (Hash, Hash.Data32);
         Data_Index := Data_Index + Fill;
         Length := Length - Data_Length_Type (Fill) * 8;

         Left := 0;
      end if;

      -- compress data until enough for a block
      while Length >= 512 loop

         -- update counter
         Hash.T32 (0) := Hash.T32 (0) + 512;

         if Hash.T32 (0) = 0 then
            Hash.T32 (1) := Hash.T32 (1) + 1;
         end if;
         Compress32 (Hash, Data (Data_Index .. Data_Index + 63));
         Data_Index := Data_Index + 64;
         Length := Length - 512;
      end loop;

      if Length > 0 then
         Hash.Data32 (Hash.Data32'First + Left .. Hash.Data32'First + Left + Natural (Length / 8) - 1) :=
           Data (Data_Index .. Data_Index + Natural (Length / 8) - 1);
         Hash.Data_Length := Data_Length_Type (Left) * 8 + Length;
         -- when non-8-multiple, add remaining bits (1 to 7)
         if Length mod 8 /= 0 then
            Hash.Data32 (Hash.Data32'First + Left + Natural (Length / 8)) := Data (Data'First + Natural (Length / 8));
         end if;
      else
         Hash.Data_Length := 0;
      end if;
   end Update32;

   procedure Update64 (Hash : in out BLAKE_State; Data : Bit_Sequence; Data_Length : Data_Length_Type) is
      Fill : Natural;
      Left : Natural; -- to handle data inputs of up to 2^64-1 bits
      Data_Index : Natural := Data'First;
      Length : Data_Length_Type := Data_Length;
   begin
      if Length = 0 and then Hash.Data_Length /= 1024 then
         return;
      end if;

      Left := Natural (Hash.Data_Length / 8);
      Fill := 128 - Left;

      -- compress remaining data filled with new bits
      if Left > 0 and then Natural (Length / 8) mod 64 >= Fill then
         Hash.Data64 (Hash.Data64'First + Left .. Hash.Data64'First + Left + Fill - 1) :=
           Data (Data_Index .. Data_Index + Fill - 1);
         -- update counter
         Hash.T64 (0) := Hash.T64 (0) + 1024;

         Compress64 (Hash, Hash.Data64);
         Data_Index := Data_Index + Fill;
         Length := Length - Data_Length_Type (Fill) * 8;

         Left := 0;
      end if;

      -- compress data until enough for a block
      while Length >= 1024 loop

         -- update counter
         Hash.T64 (0) := Hash.T64 (0) + 1024;

         Compress64 (Hash, Data (Data_Index .. Data_Index + 127));
         Data_Index := Data_Index + 128;
         Length := Length - 1024;
      end loop;

      if Length > 0 then
         Hash.Data64 (Hash.Data64'First + Left .. Hash.Data64'First + Left + Natural (Length / 8) - 1) :=
           Data (Data_Index .. Data_Index + Natural (Length / 8) - 1);
         Hash.Data_Length := Data_Length_Type (Left) * 8 + Length;
         -- when non-8-multiple, add remaining bits (1 to 7)
         if Length mod 8 /= 0 then
            Hash.Data64 (Hash.Data64'First + Left + Natural (Length / 8)) := Data (Data'First + Natural (Length / 8));
         end if;
      else
         Hash.Data_Length := 0;
      end if;
   end Update64;

   procedure Update
     (Hash      : in out BLAKE_State;
      Input     : Bit_Sequence;
      Bit_Count : Data_Length_Type)
   is
   begin
      if Hash.Hash_Length < 384 then
         Update32 (Hash, Input, Bit_Count);
      else
         Update64 (Hash, Input, Bit_Count);
      end if;
   end Update;

   procedure Final32 (Hash : in out BLAKE_State; Output : out Bit_Sequence) is
      Msglen : U8_Array (0 .. 7);
      ZZ : constant Bit_Sequence := (0 => 16#00#);
      ZO : constant Bit_Sequence := (0 => 16#01#);
      OZ : constant Bit_Sequence := (0 => 16#80#);
      OO     : constant Bit_Sequence := (0 => 16#81#);
      Low    : U32;
      High   : U32;
   begin
      -- copy nb. bits hash in total as a 64-bit BE word
      Low := Hash.T32 (0) + U32 (Hash.Data_Length);
      High := Hash.T32 (1);
      if Low < U32 (Hash.Data_Length) then
         High := High + 1;
      end if;

      Msglen (0 .. 3) := U32_To_U8 (High);
      Msglen (4 .. 7) := U32_To_U8 (Low);

      if Hash.Data_Length mod 8 = 0 then
         -- message bitlength multiple of 8

         if Hash.Data_Length = 440 then
            -- special case of one padding byte
            Hash.T32 (0) := Hash.T32 (0) - 8;
            if Hash.Hash_Length = 224 then
               Update32 (Hash, OZ, 8);
            else
               Update32 (Hash, OO, 8);
            end if;
         else
            if Hash.Data_Length < 440 then
               -- use t=0 if no remaining data
               Hash.Null_T := Hash.Data_Length = 0;
               -- enough space to fill the block
               Hash.T32 (0) := Hash.T32 (0) - (440 - U32 (Hash.Data_Length));
               Update32 (Hash, Padding, 440 - Hash.Data_Length);
            else
               -- NOT enough space, need 2 compressions
               Hash.T32 (0) := Hash.T32 (0) - (512 - U32 (Hash.Data_Length));
               Update32 (Hash, Padding, 512 - Hash.Data_Length);
               Hash.T32 (0) := Hash.T32 (0) - 440;
               Update32 (Hash, Padding (Padding'First + 1 .. Padding'Last), 440);
               Hash.Null_T := True; -- raise flag to set t=0 at the next compress
            end if;
            if Hash.Hash_Length = 224 then
               Update32 (Hash, ZZ, 8);
            else
               Update32 (Hash, ZO, 8);
            end if;
            Hash.T32 (0) := Hash.T32 (0) - 8;
         end if;
         Hash.T32 (0) := Hash.T32 (0) - 64;
         Update32 (Hash, Msglen, 64);
      else
         -- message bitlength NOT multiple of 8

         -- add '1'
         Hash.Data32 (Natural (Hash.Data_Length / 8)) := Hash.Data32 (Natural (Hash.Data_Length / 8)) and (16#FF# * 2 ** (8 - Natural (Hash.Data_Length mod 8)));
         Hash.Data32 (Natural (Hash.Data_Length / 8)) := Hash.Data32 (Natural (Hash.Data_Length / 8)) xor (16#80# / 2 ** Natural (Hash.Data_Length mod 8));

         if Hash.Data_Length > 440 and then Hash.Data_Length < 447 then
            -- special case of one padding byte
            if Hash.Hash_Length = 224 then
               Hash.Data32 (Natural (Hash.Data_Length / 8)) := Hash.Data32 (Natural (Hash.Data_Length / 8)) xor 16#00#;
            else
               Hash.Data32 (Natural (Hash.Data_Length / 8)) := Hash.Data32 (Natural (Hash.Data_Length / 8)) xor 16#01#;
            end if;
            Hash.T32 (0) := Hash.T32 (0) - (8 - U32 (Hash.Data_Length mod 8));
            -- set datalen to a 8 multiple
            Hash.Data_Length := (Hash.Data_Length and 16#fffffffffffffff8#) + 8;
         else
            if Hash.Data_Length < 440 then
               -- enough space to fill the block
               Hash.T32 (0) := Hash.T32 (0) - U32 (440 - Hash.Data_Length);
               Hash.Data_Length := (Hash.Data_Length and 16#fffffffffffffff8#) + 8;
               Update32 (Hash, Padding (Padding'First + 1 .. Padding'Last), 440 - Hash.Data_Length);
            else
               if Hash.Data_Length > 504 then
                  -- special case
                  Hash.T32 (0) := Hash.T32 (0) - U32 (512 - Hash.Data_Length);
                  Hash.Data_Length := 512;
                  Update32 (Hash, Padding (Padding'First + 1 .. Padding'Last), 0);
                  Hash.T32 (0) := Hash.T32 (0) - 440;
                  Update32 (Hash, Padding (Padding'First + 1 .. Padding'Last), 440);
                  Hash.Null_T := True; -- raise flag to set t=0 at the next compress
               else
                  -- NOT enough space, need 2 compressions
                  Hash.T32 (0) := Hash.T32 (0) - U32 (512 - Hash.Data_Length);
                  -- set datalen to a multiple of 8
                  Hash.Data_Length := (Hash.Data_Length and 16#fffffffffffffff8#) + 8;
                  Update32 (Hash, Padding (Padding'First + 1 .. Padding'Last), 512 - Hash.Data_Length);
                  Hash.T32 (0) := Hash.T32 (0) - 440;
                  Update32 (Hash, Padding (Padding'First + 1 .. Padding'Last), 440);
                  Hash.Null_T := True; -- raise flag to set t=0 at the next compress
               end if;
            end if;
            Hash.T32 (0) := Hash.T32 (0) - 8;
            if Hash.Hash_Length = 224 then
               Update32 (Hash, ZZ, 8);
            else
               Update32 (Hash, ZO, 8);
            end if;
         end if;
         Hash.T32 (0) := Hash.T32 (0) - 64;
         Update32 (Hash, Msglen, 64);
      end if;

      Output (0 .. 3) := U32_To_U8 (Hash.H32 (0));
      Output (4 .. 7) := U32_To_U8 (Hash.H32 (1));
      Output (8 .. 11) := U32_To_U8 (Hash.H32 (2));
      Output (12 .. 15) := U32_To_U8 (Hash.H32 (3));
      Output (16 .. 19) := U32_To_U8 (Hash.H32 (4));
      Output (20 .. 23) := U32_To_U8 (Hash.H32 (5));
      Output (24 .. 27) := U32_To_U8 (Hash.H32 (6));

      if Hash.Hash_Length = 256 then
         Output (28 .. 31) := U32_To_U8 (Hash.H32 (7));
      end if;
   end Final32;

   procedure Final64 (Hash : in out BLAKE_State; Output : out Bit_Sequence) is
      Msglen : U8_Array (0 .. 15);
      ZZ : constant Bit_Sequence := (0 => 16#00#);
      ZO : constant Bit_Sequence := (0 => 16#01#);
      OZ : constant Bit_Sequence := (0 => 16#80#);
      OO     : constant Bit_Sequence := (0 => 16#81#);
      Low    : U64;
      High   : U64;
   begin
      -- copy nb. bits hash in total as a 128-bit BE word
      Low := Hash.T64 (0) + Hash.Data_Length;
      High := Hash.T64 (1);
      if Low < U64 (Hash.Data_Length) then
         High := High + 1;
      end if;

      Msglen (0 .. 7) := U64_To_U8 (High);
      Msglen (8 .. 15) := U64_To_U8 (Low);

      if Hash.Data_Length mod 8 = 0 then
         -- message bitlength multiple of 8

         if Hash.Data_Length = 888 then
            -- special case of one padding byte
            Hash.T64 (0) := Hash.T64 (0) - 8;
            if Hash.Hash_Length = 384 then
               Update64 (Hash, OZ, 8);
            else
               Update64 (Hash, OO, 8);
            end if;
         else
            if Hash.Data_Length < 888 then
               -- use t=0 if no remaining data
               Hash.Null_T := Hash.Data_Length = 0;
               -- enough space to fill the block
               Hash.T64 (0) := Hash.T64 (0) - (888 - Hash.Data_Length);
               Update64 (Hash, Padding, 888 - Hash.Data_Length);
            else
               -- NOT enough space, need 2 compressions
               Hash.T64 (0) := Hash.T64 (0) - (1024 - Hash.Data_Length);
               Update64 (Hash, Padding, 1024 - Hash.Data_Length);
               Hash.T64 (0) := Hash.T64 (0) - 888;
               Update64 (Hash, Padding (Padding'First + 1 .. Padding'Last), 888);
               Hash.Null_T := True; -- raise flag to set t=0 at the next compress
            end if;
            if Hash.Hash_Length = 384 then
               Update64 (Hash, ZZ, 8);
            else
               Update64 (Hash, ZO, 8);
            end if;
            Hash.T64 (0) := Hash.T64 (0) - 8;
         end if;
         Hash.T64 (0) := Hash.T64 (0) - 128;
         Update64 (Hash, Msglen, 128);
      else
         -- message bitlength NOT multiple of 8

         -- add '1'
         Hash.Data64 (Natural (Hash.Data_Length / 8)) := Hash.Data64 (Natural (Hash.Data_Length / 8)) and (16#FF# * 2 ** (8 - Natural (Hash.Data_Length mod 8)));
         Hash.Data64 (Natural (Hash.Data_Length / 8)) := Hash.Data64 (Natural (Hash.Data_Length / 8)) xor (16#80# / 2 ** Natural (Hash.Data_Length mod 8));

         if Hash.Data_Length > 888 and then Hash.Data_Length < 895 then
            -- special case of one padding byte
            if Hash.Hash_Length = 384 then
               Hash.Data64 (Natural (Hash.Data_Length / 8)) := Hash.Data64 (Natural (Hash.Data_Length / 8)) xor ZZ (0);
            else
               Hash.Data64 (Natural (Hash.Data_Length / 8)) := Hash.Data64 (Natural (Hash.Data_Length / 8)) xor ZO (0);
            end if;
            Hash.T64 (0) := Hash.T64 (0) - (8 - Hash.Data_Length mod 8);
            -- set datalen to a 8 multiple
            Hash.Data_Length := (Hash.Data_Length and 16#fffffffffffffff8#) + 8;
         else
            if Hash.Data_Length < 888 then
               -- enough space to fill the block
               Hash.T64 (0) := Hash.T64 (0) - (888 - Hash.Data_Length);
               Hash.Data_Length := (Hash.Data_Length and 16#fffffffffffffff8#) + 8;
               Update64 (Hash, Padding (Padding'First + 1 .. Padding'Last), 888 - Hash.Data_Length);
            else
               if Hash.Data_Length > 1016 then
                  -- special case
                  Hash.T64 (0) := Hash.T64 (0) - (1024 - Hash.Data_Length);
                  Hash.Data_Length := 1024;
                  Update64 (Hash, Padding (Padding'First + 1 .. Padding'Last), 0);
                  Hash.T64 (0) := Hash.T64 (0) - 888;
                  Update64 (Hash, Padding (Padding'First + 1 .. Padding'Last), 888);
                  Hash.Null_T := True; -- raise flag to set t=0 at the next compress
               else
                  -- NOT enough space, need 2 compressions
                  Hash.T64 (0) := Hash.T64 (0) - (1024 - Hash.Data_Length);
                  -- set datalen to a multiple of 8
                  Hash.Data_Length := (Hash.Data_Length and 16#fffffffffffffff8#) + 8;
                  Update64 (Hash, Padding (Padding'First + 1 .. Padding'Last), 1024 - Hash.Data_Length);
                  Hash.T64 (0) := Hash.T64 (0) - 888;
                  Update64 (Hash, Padding (Padding'First + 1 .. Padding'Last), 888);
                  Hash.Null_T := True; -- raise flag to set t=0 at the next compress
               end if;
            end if;
            Hash.T64 (0) := Hash.T64 (0) - 8;
            if Hash.Hash_Length = 384 then
               Update64 (Hash, ZZ, 8);
            else
               Update64 (Hash, ZO, 8);
            end if;
         end if;
         Hash.T64 (0) := Hash.T64 (0) - 128;
         Update64 (Hash, Msglen, 128);
      end if;

      Output (0 .. 7) := U64_To_U8 (Hash.H64 (0));
      Output (8 .. 15) := U64_To_U8 (Hash.H64 (1));
      Output (16 .. 23) := U64_To_U8 (Hash.H64 (2));
      Output (24 .. 31) := U64_To_U8 (Hash.H64 (3));
      Output (32 .. 39) := U64_To_U8 (Hash.H64 (4));
      Output (40 .. 47) := U64_To_U8 (Hash.H64 (5));

      if Hash.Hash_Length = 512 then
         Output (48 .. 55) := U64_To_U8 (Hash.H64 (6));
         Output (56 .. 63) := U64_To_U8 (Hash.H64 (7));
      end if;
   end Final64;

   procedure Final (Hash : in out BLAKE_State; Output : out Bit_Sequence) is
   begin
      if Hash.Hash_Length < 384 then
         Final32 (Hash, Output);
      else
         Final64 (Hash, Output);
      end if;
   end Final;

   procedure Hash
     (Hash_Length : Positive;
      Input       : Bit_Sequence;
      Bit_Count   : Data_Length_Type;
      Output      : out Bit_Sequence)
   is
      State : BLAKE_State;
   begin
      -- initialise
      Init (State, Hash_Length);

      -- process message
      Update (State, Input, Bit_Count);

      -- finalise
      Final (State, Output);
   end Hash;

end SHA_3.BLAKE;
