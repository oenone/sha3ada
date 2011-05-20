package body SHA_3.JH is
   -- the constant for the round 0 of E8
   Round_Constant_0 : constant U4_Array (0 .. 63) :=
     (16#6#, 16#a#, 16#0#, 16#9#, 16#e#, 16#6#, 16#6#, 16#7#,
      16#f#, 16#3#, 16#b#, 16#c#, 16#c#, 16#9#, 16#0#, 16#8#,
      16#b#, 16#2#, 16#f#, 16#b#, 16#1#, 16#3#, 16#6#, 16#6#,
      16#e#, 16#a#, 16#9#, 16#5#, 16#7#, 16#d#, 16#3#, 16#e#,
      16#3#, 16#a#, 16#d#, 16#e#, 16#c#, 16#1#, 16#7#, 16#5#,
      16#1#, 16#2#, 16#7#, 16#7#, 16#5#, 16#0#, 16#9#, 16#9#,
      16#d#, 16#a#, 16#2#, 16#f#, 16#5#, 16#9#, 16#0#, 16#b#,
      16#0#, 16#6#, 16#6#, 16#7#, 16#3#, 16#2#, 16#2#, 16#a#);

   -- the two S-Boxes S0 and S1
   S                : constant array (U1 range 0 .. 1, U4 range  0 .. 15) of U4 :=
     (0 => (9, 0, 4, 11, 13, 12, 3, 15, 1, 10, 2, 6, 7, 5, 8, 14),
      1 => (3, 12, 6, 13, 5, 7, 1, 9, 15, 2, 0, 4, 11, 10, 14, 8));

   -- the linear transformation L, the MDS code
   procedure L (X, Y : in out U4) is
   begin
      X := X xor ((2 * X) xor (X / 8) xor ((X / 4) and 2));
      Y := Y xor ((2 * Y) xor (Y / 8) xor ((Y / 4) and 2));
   end L;

   -- the round function E8
   procedure R8 (Hash : in out JH_State) is
      Temp : U4_Array (0 .. 255);
      T    : U4;
      I    : Natural;
      -- the round constant expanded into 256 1-bit elements
      Round_Constant_Expanded : U1_Array (0 .. 255);
   begin
      -- expand the round constant into 256 one-bit elements
      for I in Round_Constant_Expanded'Range loop
         Round_Constant_Expanded (I) :=
           U1 ((Hash.Round_Constant (I / 4) / 2 ** (3-(I mod 4))) mod 2);
      end loop;

      -- S-Box layer, each constant bit selects one S-Box from S0 and S1
      for I in Temp'Range loop
         -- constant bits are used to determine which S-Box to use
         Temp (I) := S(Round_Constant_Expanded(I), Hash.A(I));
      end loop;

      -- MDS layer
      I := Temp'First;
      while I < Temp'Last loop
         L (Temp (I), Temp (I + 1));
         I := I + 2;
      end loop;

      -- the following is the permutation layer P_8

      -- initial swap Pi_8
      I := Temp'First;
      while I < Temp'Last loop
         T := Temp (I + 2);
         Temp (I + 2) := Temp (I + 3);
         Temp (I + 3) := T;
         I := I + 4;
      end loop;

      -- perutation P'_8
      for I in Hash.A'First .. Hash.A'Length / 2 - 1 loop
         Hash.A (I) := Temp (I * 2);
         Hash.A (I + 128) := Temp (I * 2 + 1);
      end loop;

      -- final swap Phi_8
      I := Hash.A'Length / 2;
      while I < Hash.A'Last loop
         T := Hash.A (I);
         Hash.A (I) := Hash.A (I + 1);
         Hash.A (I + 1) := T;
         I := I + 2;
      end loop;
   end R8;

   -- The following function generates the next round constant from the current
   -- round constant;  R6 is used for generating round constants for E8, with
   -- the round constants of R6 being set as 0;
   procedure Update_Round_Constant (Hash : in out JH_State) is
      Temp : U4_Array (0 .. 63);
      T    : U4;
      I    : Natural;
   begin
      -- S-Box layer
      for I in Temp'Range loop
         Temp (I) := S (0, Hash.Round_Constant (I));
      end loop;

      -- MDS layer
      I := Temp'First;
      while I < Temp'Last loop
         L (Temp (I), Temp (I + 1));
         I := I + 2;
      end loop;

      -- the following is the permutation layer P_6

      -- initial swap Pi_6
      I := Temp'First;
      while I < Temp'Last loop
         T := Temp (I + 2);
         Temp (I + 2) := Temp (I + 3);
         Temp (I + 3) := T;
         I := I + 4;
      end loop;

      -- permutation P'_6
      for I in Hash.Round_Constant'First .. Hash.Round_Constant'Length / 2 - 1 loop
         Hash.Round_Constant (I) := Temp (2 * I);
         Hash.Round_Constant (I + 32) := Temp (2 * I + 1);
      end loop;

      -- final swap Phi_6
      for I in Hash.Round_Constant'Length / 2 .. Hash.Round_Constant'Last - 1 loop
         T := Hash.Round_Constant (I);
         Hash.Round_Constant (I) := Hash.Round_Constant (I + 1);
         Hash.Round_Constant (I + 1) := T;
      end loop;
   end Update_Round_Constant;

   -- initial group at the begining of E_8: group the bits of H into 4-bit elements of A.
   -- After the grouping, the i-th, (i+256)-th, (i+512)-th, (i+768)-th bits of state->H
   -- become the i-th 4-bit element of state->A
   procedure E8_Initial_Group (Hash : in out JH_State) is
      T : U1_Array (0 .. 3);
      Temp : U4_Array (0 .. 255);
   begin
      -- T(0) is the i-th bit of H, i = 0 .. 127
      -- T(1) is the (i+256)-th bit of H
      -- T(2) is the (i+512)-th bit of H
      -- T(3) is the (i+768)-th bit of H
      for I in Temp'Range loop
         T (0) := U1 (Hash.H (I / 8) / 2 ** (7-(I mod 8)) mod 2);
         T (1) := U1 (Hash.H ((I + 256) / 8) / 2 ** (7-(I mod 8)) mod 2);
         T (2) := U1 (Hash.H ((I + 512) / 8) / 2 ** (7-(I mod 8)) mod 2);
         T (3) := U1 (Hash.H ((I + 768) / 8) / 2 ** (7-(I mod 8)) mod 2);
         Temp (I) := U4 (T (0)) * 8 or U4 (T (1)) * 4 or U4 (T (2)) * 2 or U4 (T (3));
      end loop;
      -- padding the odd-th elements and even-th elements separately
      for I in 0 .. 127 loop
         Hash.A (2 * I) := Temp (I);
         Hash.A (2 * I + 1) := Temp (I + 128);
      end loop;
   end E8_Initial_Group;

   -- de-group at the end of E_8:  it is the inverse of E8_initialgroup
   -- The 256 4-bit elements in state->A are degouped into the 1024-bit state->H
   procedure E8_Final_Degroup (Hash : in out JH_State) is
      T : U1_Array (0 .. 3);
      Temp : U4_Array (0 .. 255);
   begin
      for I in 0 .. 127 loop
         Temp (I) := Hash.A (2 * I);
         Temp (I + 128) := Hash.A (2 * I + 1);
      end loop;

      for I in Hash.H'Range loop
         Hash.H (I) := 0;
      end loop;

      for I in Temp'Range loop
         T (0) := U1 (Temp (I) / 8 mod 2);
         T (1) := U1 (Temp (I) / 4 mod 2);
         T (2) := U1 (Temp (I) / 2 mod 2);
         T (3) := U1 (Temp (I) / 1 mod 2);

         Hash.H (I / 8) := Hash.H (I / 8) or (U8 (T (0)) * 2 ** (7 - (I mod 8)));
         Hash.H ((I + 256) / 8) := Hash.H ((I + 256) / 8) or (U8 (T (1)) * 2 ** (7 - (I mod 8)));
         Hash.H ((I + 512) / 8) := Hash.H ((I + 512) / 8) or (U8 (T (2)) * 2 ** (7 - (I mod 8)));
         Hash.H ((I + 768) / 8) := Hash.H ((I + 768) / 8) or (U8 (T (3)) * 2 ** (7 - (I mod 8)));
      end loop;
   end E8_Final_Degroup;

   -- bijective function E8
   procedure E8 (Hash : in out JH_State) is
   begin
      -- initialize the round constant
      for I in Hash.Round_Constant'Range loop
         Hash.Round_Constant (I) := Round_Constant_0 (I);
      end loop;

      -- initial group at the beginning of E_8:
      -- group the H value into 4-bit elements and store them in A
      E8_Initial_Group (Hash);

      -- 42 rounds
      for I in 1 .. 42 loop
         R8 (Hash);
         Update_Round_Constant (Hash);
      end loop;

      -- de-group at the end of E_8:
      -- decompose the 4-bit elements of A into the 1024-bit H
      E8_Final_Degroup (Hash);
   end E8;

   -- compression function F8
   procedure F8 (Hash : in out JH_State) is
   begin
      -- xor the message with the first half of H
      for I in Hash.Buffer'Range loop
         Hash.H (I) := Hash.H (I) xor Hash.Buffer (I);
      end loop;

      -- bijective function E8
      E8 (Hash);

      -- xor the message with the last half of H
      for I in Hash.Buffer'Range loop
         Hash.H (I + 64) := Hash.H (I + 64) xor Hash.Buffer (I);
      end loop;
   end F8;

   -- before hashing a message, initialize the hash state as H0
   procedure Init (Hash : in out JH_State; Hash_Length : Positive) is
   begin
      Hash.Data_Length := 0;
      Hash.Buffer_Length := 0;

      Hash.Hash_Length := Hash_Length;

      for I in Hash.Buffer'Range loop
         Hash.Buffer (I) := 0;
      end loop;
      for I in Hash.H'Range loop
         Hash.H (I) := 0;
      end loop;

      -- initialize the initial hash value of JH
      -- step 1: set H(-1) to the message digest size
      Hash.H (1) := U8 (Hash_Length mod 256);
      Hash.H (0) := U8 ((Hash_Length / 256) mod 256);
      -- step 2: compute H0 from H(-1) with message M(0) being set as 0
      F8 (Hash);
   end Init;

   -- hash each 512-bit message block, except the last partial block
   procedure Update
     (Hash      : in out JH_State;
      Input     : Bit_Sequence;
      Bit_Count : Data_Length_Type)
   is
      Index : Natural := Input'First;
      Length : Data_Length_Type := Bit_Count;
   begin
      Hash.Data_Length := Hash.Data_Length + Length;

      -- if there is remaining data in the buffer, fill it to a full message block first
      -- we assume that the size of the data in the buffer is the multiple of 8 bits if it is not at the end of a message

      -- There is data in the buffer, but the incoming data is insufficient for a full block
      if Hash.Buffer_Length > 0 and then Data_Length_Type (Hash.Buffer_Length) + Length < 512 then
         if Length mod 8 = 0 then
            Hash.Buffer (Hash.Buffer_Length / 8 .. Hash.Buffer_Length / 8 + Natural (Length / 8) - 1)
              := Input (Index .. Index + Natural (Length / 8) - 1);
         else
            Hash.Buffer (Hash.Buffer_Length / 8 .. Hash.Buffer_Length / 8 + Natural (Length / 8))
              := Input (Index .. Index + Natural (Length / 8));
         end if;
         Hash.Buffer_Length := Hash.Buffer_Length + Natural (Length);
         Length := 0;
      end if;

      -- There is data in the buffer, and the incoming data is sufficient for a full block
      if Hash.Buffer_Length > 0 and then Data_Length_Type (Hash.Buffer_Length) + Length >= 512 then
         Hash.Buffer (Hash.Buffer_Length / 8 .. Hash.Buffer'Last) :=
           Input (Index .. Index + Hash.Buffer'Length - Hash.Buffer_Length / 8 - 1);
         Index := Index + Hash.Buffer'Length - Hash.Buffer_Length / 8;
         Length := Length - Data_Length_Type (512 - Hash.Buffer_Length);
         F8 (Hash);
         Hash.Buffer_Length := 0;
      end if;

      -- hash the remaining full message blocks
      while Length >= 512 loop
         Hash.Buffer := Input (Index .. Index + 63);
         F8 (Hash);
         Index := Index + 64;
         Length := Length - 512;
      end loop;

      -- store the partial block into buffer, assume that
      -- if part of the last byte is not part of the message, then that part consists of 0 bits
      if Length > 0 then
         if Length mod 8 = 0 then
            Hash.Buffer (0 .. Natural (Length / 8) - 1) := Input (Index .. Index + Natural (Length / 8) - 1);
         else
            Hash.Buffer (0 .. Natural (Length / 8)) := Input (Index .. Index + Natural (Length / 8));
         end if;
         Hash.Buffer_Length := Natural (Length);
      end if;
   end Update;

   -- padding the message, truncate the hash value H and obtain the message digest
   procedure Final (Hash : in out JH_State; Output : out Bit_Sequence) is
   begin
      if Hash.Data_Length mod 512 = 0 then
         -- pad the message when databitlen is multiple of 512 bits, then process the padded block
         for I in Hash.Buffer'Range loop
            Hash.Buffer (I) := 0;
         end loop;
         Hash.Buffer (Hash.Buffer'First) := 16#80#;
         for I in 0 .. 7 loop
            Hash.Buffer (Hash.Buffer'Last - I) := U8 ((Hash.Data_Length / 256 ** I) mod 256);
         end loop;
         F8 (Hash);
      else
         -- set the rest of the bytes in the buffer to 0
         if Hash.Buffer_Length mod 8 = 0 then
            for I in Natural (Hash.Data_Length mod 512) / 8 .. Hash.Buffer'Last loop
               Hash.Buffer (I) := 0;
            end loop;
         else
            for I in Natural (Hash.Data_Length mod 512) / 8 + 1 .. Hash.Buffer'Last loop
               Hash.Buffer (I) := 0;
            end loop;
         end if;

         -- pad and process the partial block when databitlen is not multiple of 512 bits, then hash the padded blocks
         Hash.Buffer (Natural (Hash.Data_Length mod 512) / 8) :=
           Hash.Buffer (Natural (Hash.Data_Length mod 512) / 8) or
           2 ** (7-Natural (Hash.Data_Length mod 8));
         F8 (Hash);
         for I in Hash.Buffer'Range loop
            Hash.Buffer (I) := 0;
         end loop;
         Hash.Buffer (Hash.Buffer'First) := 16#80#;
         for I in 0 .. 7 loop
            Hash.Buffer (Hash.Buffer'Last - I) := U8 ((Hash.Data_Length / 256 ** I) mod 256);
         end loop;
         F8 (Hash);
      end if;

      -- trunacting the final hash value to generate the message digest
      case Hash.Hash_Length is
         when 224 =>
            Output := Hash.H (100 .. Hash.H'Last);
         when 256 =>
            Output := Hash.H (96 .. Hash.H'Last);
         when 384 =>
            Output := Hash.H (80 .. Hash.H'Last);
         when 512 =>
            Output := Hash.H (64 .. Hash.H'Last);
         when others =>
            raise BAD_HASH_LENGTH;
      end case;
   end Final;

   -- hash a message,
   -- three inputs: message digest size in bits (Hash_Length); message (Input); message length in bits (Bit_Count)
   -- one output:   message digest (Output)
   procedure Hash
     (Hash_Length : Positive;
      Input       : Bit_Sequence;
      Bit_Count   : Data_Length_Type;
      Output      : out Bit_Sequence)
   is
      Hash : JH_State;
   begin
      if Hash_Length = 224 or else Hash_Length = 256 or else
        Hash_Length = 384 or else Hash_Length = 512 then
         Init (Hash, Hash_Length);
         Update (Hash, Input, Bit_Count);
         Final (Hash, Output);
      else
         raise BAD_HASH_LENGTH;
      end if;
   end Hash;

end SHA_3.JH;
