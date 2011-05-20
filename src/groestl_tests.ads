with Ahven.Framework;

package Groestl_Tests is
   type Test is new Ahven.Framework.Test_Case with null record;
   procedure Initialize (T : in out Test);
   procedure Test_224_Bits_1;
   procedure Test_224_Bits_2;
   procedure Test_256_Bits_1;
   procedure Test_256_Bits_2;
   procedure Test_384_Bits_1;
   procedure Test_384_Bits_2;
   procedure Test_512_Bits_1;
   procedure Test_512_Bits_2;
end Groestl_Tests;
