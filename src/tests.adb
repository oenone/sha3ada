with Ahven.Text_Runner;
with Ahven.Framework;
with Groestl_Tests;
with BLAKE_Tests;
with JH_Tests;

procedure Tests is
   S : constant Ahven.Framework.Test_Suite_Access :=
     Ahven.Framework.Create_Suite ("SHA-3 Tests");
begin
   Ahven.Framework.Add_Test (S.all, new Groestl_Tests.Test);
   Ahven.Framework.Add_Test (S.all, new BLAKE_Tests.Test);
   Ahven.Framework.Add_Test (S.all, new JH_Tests.Test);
   Ahven.Text_Runner.Run (S);
   Ahven.Framework.Release_Suite (S);
end Tests;
