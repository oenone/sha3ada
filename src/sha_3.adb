package body SHA_3 is

   function U8_To_U32 (From : U8_Array) return U32 is
      Result : U32 := 0;
   begin
      if From'Length /= 4 then
         raise Constraint_Error;
      end if;
      for I in From'Range loop
         Result := Result * 2 ** 8;
         Result := Result + U32 (From (I));
      end loop;
      return Result;
   end U8_To_U32;

   function U8_To_U64 (From : U8_Array) return U64 is
      Result : U64 := 0;
   begin
      if From'Length /= 8 then
         raise Constraint_Error;
      end if;
      for I in From'Range loop
         Result := Result * 2 ** 8;
         Result := Result + U64 (From (I));
      end loop;
      return Result;
   end U8_To_U64;

   function U32_To_U8 (From : U32) return U8_Array is
      Result : U8_Array (0 .. 3);
      Value  : U32 := From;
   begin
      for I in reverse Result'Range loop
         Result (I) := U8 (Value mod 2 ** 8);
         Value := Value / 2 ** 8;
      end loop;
      return Result;
   end U32_To_U8;

   function U64_To_U8 (From : U64) return U8_Array is
      Result : U8_Array (0 .. 7);
      Value  : U64 := From;
   begin
      for I in reverse Result'Range loop
         Result (I) := U8 (Value mod 2 ** 8);
         Value := Value / 2 ** 8;
      end loop;
      return Result;
   end U64_To_U8;

   function U8_To_Hex (X : U8) return U8_String is
      Hex_Chars : constant array (SHA_3.U8 range <>) of Character :=
        ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f');
      Result : U8_String;
   begin
      Result (1) := Hex_Chars (X / 16);
      Result (2) := Hex_Chars (X mod 16);
      return Result;
   end U8_To_Hex;

   function Hex_To_U8 (S : String) return U8 is
      Hex_Chars_1 : constant array (SHA_3.U8 range <>) of Character :=
        ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f');
      Hex_Chars_2 : constant array (SHA_3.U8 range <>) of Character :=
        ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F');
      Result    : U8 := 0;
   begin
      for I in S'Range loop
         Result := Result * 16;
         for J in Hex_Chars_1'Range loop
            if Hex_Chars_1 (J) = S (I) or else Hex_Chars_2 (J) = S (I) then
               Result := Result + J;
            end if;
         end loop;
      end loop;
      return Result;
   end Hex_To_U8;

   function String_To_Bit_Sequence (S : String) return Bit_Sequence is
      Result : Bit_Sequence (0 .. S'Length - 1);
      Result_Idx : Natural := Result'First;
   begin
      for I in S'Range loop
         Result (Result_Idx) := U8 (Character'Pos (S (I)));
         Result_Idx := Result_Idx + 1;
      end loop;
      return Result;
   end String_To_Bit_Sequence;

   function Hex_String_To_Bit_Sequence (S : String) return Bit_Sequence is
      Result : Bit_Sequence (0 .. S'Length / 2 - 1);
   begin
      if S'Length mod 2 /= 0 then
         return Hex_String_To_Bit_Sequence ("0" & S);
      end if;
      for I in Result'Range loop
         Result (I) := Hex_To_U8 (S (S'First + 2 * I .. S'First + 2 * I + 1));
      end loop;
      return Result;
   end Hex_String_To_Bit_Sequence;

   function Bit_Sequence_To_String (B : Bit_Sequence) return String is
      Result : String (1 .. B'Length);
      Result_Idx : Natural := Result'First;
   begin
      for I in B'Range loop
         Result (Result_Idx) := Character'Val (B (I));
         Result_Idx := Result_Idx + 1;
      end loop;
      return Result;
   end Bit_Sequence_To_String;

   function Bit_Sequence_To_Hex_String (B : Bit_Sequence) return String is
      Result : String (1 .. B'Length * 2);
      Result_Index : Natural := Result'First;
   begin
      for I in B'Range loop
         Result (Result_Index .. Result_Index + 1) := U8_To_Hex (B (I));
         Result_Index := Result_Index + 2;
      end loop;
      return Result;
   end Bit_Sequence_To_Hex_String;

end SHA_3;
