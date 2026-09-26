.class private auto ansi beforefieldinit ToyDropper.Program
	extends [System.Runtime]System.Object
{
	.method private hidebysig static 
		void Main (
			string[] args
		) cil managed 
	{
		.entrypoint
		.maxstack 8
		IL_0000: ldstr "aHR0cDovL2MyLmV4YW1wbGUuaW52YWxpZC9nYXRl"
		IL_0005: call string ToyDropper.Program::Decode(string)
		IL_000a: ret
	} // end of method Program::Main

	.method private hidebysig static 
		string Decode (
			string s
		) cil managed 
	{
		.maxstack 8
		IL_0000: ldarg.0
		IL_0001: call uint8[] [System.Runtime]System.Convert::FromBase64String(string)
		IL_0006: ret
	} // end of method Program::Decode
}
