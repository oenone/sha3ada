package body SHA_3.Groestl is

   function Mul2 (B : U8) return U8 is
   begin
      if B / 2 ** 7 > 0 then
         return (B * 2) xor 16#1B#;
      else
         return B * 2;
      end if;
   end Mul2;
   function Mul3 (B : U8) return U8 is
   begin
      return Mul2 (B) xor B;
   end Mul3;
   function Mul4 (B : U8) return U8 is
   begin
      return Mul2 (Mul2 (B));
   end Mul4;
   function Mul5 (B : U8) return U8 is
   begin
      return Mul4 (B) xor B;
   end Mul5;
   function Mul7 (B : U8)return U8 is
   begin
      return Mul4 (B) xor Mul2 (B) xor B;
   end Mul7;

   -- S-Box
   S : constant U8_Array (0 .. 2 ** 8 - 1) :=
     (16#63#, 16#7c#, 16#77#, 16#7b#, 16#f2#, 16#6b#, 16#6f#, 16#c5#,
      16#30#, 16#01#, 16#67#, 16#2b#, 16#fe#, 16#d7#, 16#ab#, 16#76#,
      16#ca#, 16#82#, 16#c9#, 16#7d#, 16#fa#, 16#59#, 16#47#, 16#f0#,
      16#ad#, 16#d4#, 16#a2#, 16#af#, 16#9c#, 16#a4#, 16#72#, 16#c0#,
      16#b7#, 16#fd#, 16#93#, 16#26#, 16#36#, 16#3f#, 16#f7#, 16#cc#,
      16#34#, 16#a5#, 16#e5#, 16#f1#, 16#71#, 16#d8#, 16#31#, 16#15#,
      16#04#, 16#c7#, 16#23#, 16#c3#, 16#18#, 16#96#, 16#05#, 16#9a#,
      16#07#, 16#12#, 16#80#, 16#e2#, 16#eb#, 16#27#, 16#b2#, 16#75#,
      16#09#, 16#83#, 16#2c#, 16#1a#, 16#1b#, 16#6e#, 16#5a#, 16#a0#,
      16#52#, 16#3b#, 16#d6#, 16#b3#, 16#29#, 16#e3#, 16#2f#, 16#84#,
      16#53#, 16#d1#, 16#00#, 16#ed#, 16#20#, 16#fc#, 16#b1#, 16#5b#,
      16#6a#, 16#cb#, 16#be#, 16#39#, 16#4a#, 16#4c#, 16#58#, 16#cf#,
      16#d0#, 16#ef#, 16#aa#, 16#fb#, 16#43#, 16#4d#, 16#33#, 16#85#,
      16#45#, 16#f9#, 16#02#, 16#7f#, 16#50#, 16#3c#, 16#9f#, 16#a8#,
      16#51#, 16#a3#, 16#40#, 16#8f#, 16#92#, 16#9d#, 16#38#, 16#f5#,
      16#bc#, 16#b6#, 16#da#, 16#21#, 16#10#, 16#ff#, 16#f3#, 16#d2#,
      16#cd#, 16#0c#, 16#13#, 16#ec#, 16#5f#, 16#97#, 16#44#, 16#17#,
      16#c4#, 16#a7#, 16#7e#, 16#3d#, 16#64#, 16#5d#, 16#19#, 16#73#,
      16#60#, 16#81#, 16#4f#, 16#dc#, 16#22#, 16#2a#, 16#90#, 16#88#,
      16#46#, 16#ee#, 16#b8#, 16#14#, 16#de#, 16#5e#, 16#0b#, 16#db#,
      16#e0#, 16#32#, 16#3a#, 16#0a#, 16#49#, 16#06#, 16#24#, 16#5c#,
      16#c2#, 16#d3#, 16#ac#, 16#62#, 16#91#, 16#95#, 16#e4#, 16#79#,
      16#e7#, 16#c8#, 16#37#, 16#6d#, 16#8d#, 16#d5#, 16#4e#, 16#a9#,
      16#6c#, 16#56#, 16#f4#, 16#ea#, 16#65#, 16#7a#, 16#ae#, 16#08#,
      16#ba#, 16#78#, 16#25#, 16#2e#, 16#1c#, 16#a6#, 16#b4#, 16#c6#,
      16#e8#, 16#dd#, 16#74#, 16#1f#, 16#4b#, 16#bd#, 16#8b#, 16#8a#,
      16#70#, 16#3e#, 16#b5#, 16#66#, 16#48#, 16#03#, 16#f6#, 16#0e#,
      16#61#, 16#35#, 16#57#, 16#b9#, 16#86#, 16#c1#, 16#1d#, 16#9e#,
      16#e1#, 16#f8#, 16#98#, 16#11#, 16#69#, 16#d9#, 16#8e#, 16#94#,
      16#9b#, 16#1e#, 16#87#, 16#e9#, 16#ce#, 16#55#, 16#28#, 16#df#,
      16#8c#, 16#a1#, 16#89#, 16#0d#, 16#bf#, 16#e6#, 16#42#, 16#68#,
      16#41#, 16#99#, 16#2d#, 16#0f#, 16#b0#, 16#54#, 16#bb#, 16#16#);

   -- Shift values for short/long variants
   Shift : constant array (Variant, 0 .. ROWS - 1) of Natural :=
     (P512 => (0, 1, 2, 3, 4, 5, 6, 7), P1024 => (0, 1, 2, 3, 4, 5, 6, 11),
      Q512 => (1, 3, 5, 7, 0, 2, 4, 6), Q1024 => (1, 3, 5, 11, 0, 2, 4, 6));

   -- Add_Round_Constant xors a round-dependant constant to the state
   procedure Add_Round_Constant (X     : in out U8_Array_2D; Columns : Natural;
                                 Round : U8; V : Variant) is
   begin
      case V is
         when Q512 | Q1024 =>
            for I in 0 .. Columns - 1 loop
               for J in 0 .. ROWS - 2 loop
                  X (J, I) := X (J, I) xor 16#FF#;
               end loop;
            end loop;
            for I in 0 .. Columns - 1 loop
               X (ROWS - 1, I) := X (ROWS - 1, I) xor (U8 (I * 16#10#) xor 16#FF# xor Round);
            end loop;
         when P512 | P1024 =>
            for I in 0 .. Columns - 1 loop
               X (0, I) := X (0, I) xor (U8 (I * 16#10#) xor Round);
            end loop;
      end case;
   end Add_Round_Constant;

   -- Sub_Bytes replaces each byte by a value from the S-box
   procedure Sub_Bytes (X : in out U8_Array_2D; Columns : Natural) is
   begin
      for I in 0 .. ROWS - 1 loop
         for J in 0 .. Columns - 1 loop
            X (I, J) := S (Natural (X (I, J)));
         end loop;
      end loop;
   end Sub_Bytes;

   -- Shift_Bytes cyclically shifts each row to the left by a number of
   -- positions
   procedure Shift_Bytes (X : in out U8_Array_2D; Columns : Natural; V : Variant) is
      R    : array (0 .. ROWS - 1) of Natural;
      Temp : U8_Array (0 .. Columns - 1);
   begin
      for I in 0 .. ROWS - 1 loop
         R (I) := Shift (V, I);
      end loop;
      for I in 0 .. ROWS - 1 loop
         for J in 0 .. Columns - 1 loop
            Temp (J) := X (I, (J + R (I)) mod Columns);
         end loop;
         for J in 0 .. Columns - 1 loop
            X (I, J) := Temp (J);
         end loop;
      end loop;
   end Shift_Bytes;

   -- Mix_Bytes reversibly mixes the bytes within a column
   procedure Mix_Bytes (X : in out U8_Array_2D; Columns : Natural) is
      Temp : U8_Array (0 .. ROWS - 1);
   begin
      for I in 0 .. Columns - 1 loop
         for J in 0 .. ROWS - 1 loop
            Temp (J) :=
              Mul2 (X ((J + 0) mod ROWS, I)) xor
              Mul2 (X ((J + 1) mod ROWS, I)) xor
              Mul3 (X ((J + 2) mod ROWS, I)) xor
              Mul4 (X ((J + 3) mod ROWS, I)) xor
              Mul5 (X ((J + 4) mod ROWS, I)) xor
              Mul3 (X ((J + 5) mod ROWS, I)) xor
              Mul5 (X ((J + 6) mod ROWS, I)) xor
              Mul7 (X ((J + 7) mod ROWS, I));
         end loop;
         for J in 0 .. ROWS - 1 loop
            X (J, I) := Temp (J);
         end loop;
      end loop;
   end Mix_Bytes;

   -- apply P-permutation to x
   procedure P (Hash : Groestl_State; X : in out U8_Array_2D) is
      V : Variant;
   begin
      if Hash.Columns = 8 then
         V := P512;
      else
         V := P1024;
      end if;
      for I in 0 .. Hash.Rounds - 1 loop
         Add_Round_Constant (X, Hash.Columns, U8 (I), V);
         Sub_Bytes (X, Hash.Columns);
         Shift_Bytes (X, Hash.Columns, V);
         Mix_Bytes (X, Hash.Columns);
      end loop;
   end P;

   -- apply Q-permutation to x
   procedure Q (Hash : Groestl_State; X : in out U8_Array_2D) is
      V : Variant;
   begin
      if Hash.Columns = 8 then
         V := Q512;
      else
         V := Q1024;
      end if;
      for I in 0 .. Hash.Rounds - 1 loop
         Add_Round_Constant (X, Hash.Columns, U8 (I), V);
         Sub_Bytes (X, Hash.Columns);
         Shift_Bytes (X, Hash.Columns, V);
         Mix_Bytes (X, Hash.Columns);
      end loop;
   end Q;

   -- digest (up to) msglen bytes
   procedure Transform (Hash : in out Groestl_State; Input : Bit_Sequence) is
      Temp1, Temp2   : U8_Array_2D (0 .. ROWS - 1, 0 .. Hash.Columns - 1);
      Message_Length : Natural := Input'Length;
      Start_Index    : Natural := Input'First;
   begin
      -- digest one message block at the time
      while Message_Length >= Hash.State_Size loop
         -- store message block (m) in temp2, and xor of chaining (h) and
         -- message block in temp1
         for I in 0 .. ROWS - 1 loop
            for J in 0 .. Hash.Columns - 1 loop
               Temp1 (I, J) := Hash.Chaining (I, J) xor Input (J * ROWS + I);
               Temp2 (I, J) := Input (J * ROWS + I);
            end loop;
         end loop;

         -- P (h+m)
         P (Hash, Temp1);
         -- Q (m)
         Q (Hash, Temp2);

         -- xor P(h+m) and Q(m) onto chaining, yielding P(h+m)+Q(m)+h
         for I in 0 .. ROWS - 1 loop
            for J in 0 .. Hash.Columns - 1 loop
               Hash.Chaining (I, J) := Hash.Chaining (I, J) xor (Temp1 (I, J) xor Temp2 (I, J));
            end loop;
         end loop;

         -- increment block counter
         Hash.Block_Counter := Hash.Block_Counter + 1;
         Message_Length := Message_Length - Hash.State_Size;
         Start_Index := Start_Index + Hash.State_Size;
      end loop;
   end Transform;

   -- do output transformation, P(h)+h
   procedure Output_Transformation (Hash : in out Groestl_State) is
      Temp : U8_Array_2D (0 .. ROWS - 1, 0 .. Hash.Columns - 1);
   begin
      -- store chaining ("h") in temp
      for I in 0 .. ROWS - 1 loop
         for J in 0 .. Hash.Columns - 1 loop
            Temp (I, J) := Hash.Chaining (I, J);
         end loop;
      end loop;

      -- compute P(temp) = P(h)
      P (Hash, Temp);

      -- feed chaining forward, yielding P(h)+h
      for I in 0 .. ROWS - 1 loop
         for J in 0 .. Hash.Columns - 1 loop
            Hash.Chaining (I, J) := Hash.Chaining (I, J) xor Temp (I, J);
         end loop;
      end loop;
   end Output_Transformation;

   -- initialise context
   procedure Init (Hash : in out Groestl_State; Hash_Length : Positive) is
   begin
      if Hash_Length mod 8 /= 0 or else Hash_Length > 512 then
         raise BAD_HASH_LENGTH;
      end if;

      if Hash_Length <= 256 then
         Hash.Rounds := ROUNDS512;
         Hash.Columns := COLS512;
         Hash.State_Size := SIZE512;
      else
         Hash.Rounds := ROUNDS1024;
         Hash.Columns := COLS1024;
         Hash.State_Size := SIZE1024;
      end if;

      -- zeroise chaining variable
      for I in 0 .. ROWS - 1 loop
         for J in 0 .. Hash.Columns - 1 loop
            Hash.Chaining (I, J) := 0;
         end loop;
      end loop;

      -- store hashbitlen and set initial value
      Hash.Hash_Length := Hash_Length;
      for I in ROWS - Integer'Size / 8 .. ROWS - 1 loop
         Hash.Chaining (I, Hash.Columns - 1) := U8 ((Hash_Length / 2 ** (8 * (7 - I))) mod 2 ** 8);
      end loop;

      -- initialise other variables
      Hash.Buffer_Index := Hash.Buffer'First;
      Hash.Block_Counter := 0;
      Hash.Bits_In_Last_Byte := 0;
   end Init;

   procedure Update (Hash : in out Groestl_State; Input : Bit_Sequence; Bit_Count : Data_Length_Type) is
      -- no. of (full) bytes supplied
      Message_Length : constant Natural := Natural (Bit_Count / 8);
      -- no. of additional bits
      Remainder      : constant Natural := Natural (Bit_Count mod 8);
      Index          : Natural := Input'First;
   begin
      if Hash.Bits_In_Last_Byte /= 0 then
         raise FAIL;
      end if;

      -- if the buffer contains data that still needs to be digested
      if Hash.Buffer_Index /= 0 then
         -- copy data into buffer until buffer is full, or there is no more
         -- data
         Index := 0;
         while Hash.Buffer_Index < Hash.State_Size and then Index < Message_Length loop
            Hash.Buffer (Hash.Buffer_Index) := Input (Index);
            Index := Index + 1;
            Hash.Buffer_Index := Hash.Buffer_Index + 1;
         end loop;

         if Hash.Buffer_Index < Hash.State_Size then
            -- this chunk of message does not fill the buffer
            if Remainder > 0 then
               -- if there are additional bits, add them to the buffer
               Hash.Bits_In_Last_Byte := Remainder;
               Hash.Buffer (Hash.Buffer_Index) := Input (Index);
               Hash.Buffer_Index := Hash.Buffer_Index + 1;
            end if;
            return;
         end if;

         -- the buffer is full, digest
         Hash.Buffer_Index := 0;
         Transform (Hash, Hash.Buffer (0 .. Hash.State_Size / 8 - 1));
      end if;

      -- digest remainder of data modulo the block size
      Transform (Hash, Input (Index .. Index + Message_Length - 1));
      Index := Index + ((Message_Length - Index) / Hash.State_Size) * Hash.State_Size;

      -- copy remaining data to buffer
      while Index < Message_Length loop
         Hash.Buffer (Hash.Buffer_Index) := Input (Index);
         Index := Index + 1;
         Hash.Buffer_Index := Hash.Buffer_Index + 1;
      end loop;

      if Remainder /= 0 then
         Hash.Bits_In_Last_Byte := Remainder;
         Hash.Buffer (Hash.Buffer_Index) := Input (Index);
         Hash.Buffer_Index := Hash.Buffer_Index + 1;
      end if;
   end Update;

   procedure Final (Hash : in out Groestl_State; Output : out Bit_Sequence) is
      Hash_Byte_Length : constant Natural := Hash.Hash_Length / 8;
      BILB             : Natural renames Hash.Bits_In_Last_Byte;
   begin
      -- 100... padding
      if Hash.Bits_In_Last_Byte /= 0 then
         Hash.Buffer (Hash.Buffer_Index - 1) := Hash.Buffer (Hash.Buffer_Index - 1) and
           ((2 ** BILB - 1) * 2 ** (8 - BILB));
         Hash.Buffer (Hash.Buffer_Index - 1) := Hash.Buffer (Hash.Buffer_Index - 1) xor
           2 ** (7 - BILB);
      else
         Hash.Buffer (Hash.Buffer_Index) := 16#80#;
         Hash.Buffer_Index := Hash.Buffer_Index + 1;
      end if;

      if Hash.Buffer_Index > Hash.State_Size - LENGTHFIELDLENGTH then
         -- padding requires two blocks
         while Hash.Buffer_Index < Hash.State_Size loop
            Hash.Buffer (Hash.Buffer_Index) := 0;
            Hash.Buffer_Index := Hash.Buffer_Index + 1;
         end loop;
         Transform (Hash, Hash.Buffer (0 .. Hash.State_Size - 1));
         Hash.Buffer_Index := 0;
      end if;
      while Hash.Buffer_Index < Hash.State_Size - LENGTHFIELDLENGTH loop
         Hash.Buffer (Hash.Buffer_Index) := 0;
         Hash.Buffer_Index := Hash.Buffer_Index + 1;
      end loop;

      -- length padding
      Hash.Block_Counter := Hash.Block_Counter + 1;
      Hash.Buffer_Index := Hash.State_Size;
      while Hash.Buffer_Index > Hash.State_Size - LENGTHFIELDLENGTH loop
         Hash.Buffer_Index := Hash.Buffer_Index - 1;
         Hash.Buffer (Hash.Buffer_Index) := U8 (Hash.Block_Counter);
         Hash.Block_Counter := Hash.Block_Counter / 2**8;
      end loop;

      -- digest (last) padding block
      Transform (Hash, Hash.Buffer (0 .. Hash.State_Size - 1));
      -- output transformation
      Output_Transformation (Hash);

      -- store hash output
      declare
         J : Natural := 0;
         I : Natural := Hash.State_Size - Hash_Byte_Length;
      begin
         while I < Hash.State_Size loop
            Output (J) := Hash.Chaining (I mod ROWS, I / ROWS);
            I := I + 1;
            J := J + 1;
         end loop;
      end;

      -- zeroise
      for I in 0 .. ROWS - 1 loop
         for J in 0 .. Hash.Columns - 1 loop
            Hash.Chaining (I, J) := 0;
         end loop;
      end loop;
      for I in 0 .. Hash.State_Size - 1 loop
         Hash.Buffer (I) := 0;
      end loop;
   end Final;

   -- hash bit sequence
   procedure Hash
     (Hash_Length : Positive;
      Input       : Bit_Sequence;
      Bit_Count   : Data_Length_Type;
      Output      : out Bit_Sequence)
   is
      State : Groestl_State;
   begin
      -- initialise
      Init (State, Hash_Length);

      -- process message
      Update (State, Input, Bit_Count);

      -- finalise
      Final (State, Output);
   end Hash;

end SHA_3.Groestl;
