using Microsoft.Win32;
using System.Diagnostics.Contracts;
using System.Runtime.InteropServices;


RegistryKey regmenu = null;
RegistryKey regcmd = null;

string loc = AppContext.BaseDirectory;

//Setup folder menu
try
{
    string MenuName = "Folder\\shell\\cry_locker";
    string command = "Folder\\shell\\cry_locker\\command";
    regmenu = Registry.ClassesRoot.CreateSubKey(MenuName);
    if (regmenu != null)
    {
        regmenu.SetValue("", "Encrypt");
    }
    regcmd = Registry.ClassesRoot.CreateSubKey(command);
    if (regcmd != null)
    {
        regcmd.SetValue("", "cmd /c cry_locker -e \"%1\"");
    }
}
catch (Exception e)
{
    Console.WriteLine(e.Message);
    Console.ReadLine();
    throw;
}
finally
{
    if (regmenu != null) regmenu.Close();
    if (regcmd != null) regcmd.Close();
}

//Setup the file menu
/*try
{
    string MenuName = "*\\shell\\cry_locker";
    string command = "*\\shell\\cry_locker\\command";
    regmenu = Registry.ClassesRoot.CreateSubKey(MenuName);
    if (regmenu != null)
    {
        regmenu.SetValue("", "Encrypt");
    }
    regcmd = Registry.ClassesRoot.CreateSubKey(command);
    if (regcmd != null)
    {
        regcmd.SetValue("", "cmd /k cry_locker -e \"%1\"");
    }
}
catch (Exception e)
{
    Console.WriteLine(e.Message);
    Console.ReadLine();
    throw;
}
finally
{
    if (regmenu != null) regmenu.Close();
    if (regcmd != null) regcmd.Close();
}*/

//reset
regmenu = null;
regcmd = null;

//Setup .cry_locker menu
try
{
    string MenuName = ".cry_locker\\shell\\cry_locker";
    string command = ".cry_locker\\shell\\cry_locker\\command";
    regmenu = Registry.ClassesRoot.CreateSubKey(MenuName);
    if (regmenu != null)
    {
        regmenu.SetValue("", "Decrypt");
    }
    regcmd = Registry.ClassesRoot.CreateSubKey(command);
    if (regcmd != null)
    {
        regcmd.SetValue("", "cmd /c cry_locker -d \"%1\"");
    }
}
catch (Exception e)
{
    Console.WriteLine(e.Message);
    Console.ReadLine();
    throw;
}
finally
{
    if (regmenu != null) regmenu.Close();
    if (regcmd != null) regcmd.Close();
}

//Setup environment path
try
{
	const int HWND_BROADCAST = 0xffff;
	const uint WM_SETTINGCHANGE = 0x001a;

	[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
	static extern bool SendNotifyMessage(IntPtr hWnd, uint Msg,
			UIntPtr wParam, string lParam);

	using var envKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", true);
	Contract.Assert(envKey != null, @"registry key is missing!");
	FileInfo f = new FileInfo(loc);

	//envKey.SetValue("cry_locker", $"{f.DirectoryName}");
	string key = envKey.GetValue("Path").ToString();
	envKey.SetValue("Path", $"{key}{f.DirectoryName};");

    //Tell windows to refresh
	SendNotifyMessage((IntPtr)HWND_BROADCAST, WM_SETTINGCHANGE, (UIntPtr)0, "Environment");

}
catch (Exception)
{

	throw;
}