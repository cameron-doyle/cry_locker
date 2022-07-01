using Microsoft.Win32;
using System.Diagnostics.Contracts;
using System.Runtime.InteropServices;

RegistryKey? regmenu = null;
RegistryKey? regcmd = null;

string ext = "cry_locker";
string exeName = "cry_locker.exe";

string loc = AppContext.BaseDirectory;


//Setup encrypt menu for folders (excludes recycle bin)
try
{
    string MenuName = $"Folder\\shell\\{exeName}";
    string command = $"Folder\\shell\\{exeName}\\command";
    regmenu = Registry.ClassesRoot.CreateSubKey(MenuName);
    if (regmenu != null)
    {
        regmenu.SetValue("", "Encrypt"); //Context menu entry
        regmenu.SetValue("Icon", $"{loc}{exeName}"); //Icon for the context menu
        regmenu.SetValue("AppliesTo", "System.FileName:?*"); //Prevents special folders like recycle bin from showing up
    }
    regcmd = Registry.ClassesRoot.CreateSubKey(command);
    if (regcmd != null)
    {
        regcmd.SetValue("", $"cmd /c {exeName} -e \"%1\""); //CMD that is run when the context menu item is selected
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


regmenu = null;
regcmd = null;

//Setup encrypt menu for files
try
{
    string MenuName = $"*\\shell\\{exeName}";
    string command = $"*\\shell\\{exeName}\\command";
    regmenu = Registry.ClassesRoot.CreateSubKey(MenuName);
    if (regmenu != null)
    {
        regmenu.SetValue("", "Encrypt"); //Context menu entry
        regmenu.SetValue("Icon", $"{loc}{exeName}"); //Icon for the context menu
        //regmenu.SetValue("Position", "Top"); This makes the encrypt option appear on top of .cry_locker files, which isn't ideal
    }
    regcmd = Registry.ClassesRoot.CreateSubKey(command);
    if (regcmd != null)
    {
        regcmd.SetValue("", $"cmd /c {exeName} -e \"%1\""); //CMD that is run when the context menu item is selected
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


//reset
regmenu = null;
regcmd = null;
RegistryKey? ico = null;

//Setup decrypt menu
try
{
    string MenuName = $".{ext}\\shell\\{exeName}";
    string command = $".{ext}\\shell\\{exeName}\\command";
    string icon = $".{ext}\\DefaultIcon";
    regmenu = Registry.ClassesRoot.CreateSubKey(MenuName);
    if (regmenu != null)
    {
        regmenu.SetValue("", "Decrypt");
        regmenu.SetValue("Icon", $"{loc}{exeName}");
        regmenu.SetValue("Position", "Top");
    }
    ico = Registry.ClassesRoot.CreateSubKey(icon);
    if(ico != null)
	{
        ico.SetValue("", $"{loc}{exeName}");
    }
    regcmd = Registry.ClassesRoot.CreateSubKey(command);
    if (regcmd != null)
    {
        regcmd.SetValue("", $"cmd /c {exeName} -d \"%1\"");
    }

/*    var ins = Registry.ClassesRoot.CreateSubKey($".{exeName}\\DefaultIcon");
    if(ins != null)
	{
        string p = $"{loc}{exeName}";
        ins.SetValue("", p);
    }*/
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
    if (ico != null) ico.Close();

}

//reset
regmenu = null;
regcmd = null;

//Set icon for file
/*try
{
    regmenu = Registry.ClassesRoot.CreateSubKey($".{ext}\\DefaultIcon");
    if (regmenu != null)
    {
        string p = $"{loc}{exeName}";
        regmenu.SetValue("", p);
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


    //Get current env variables.
    string key = envKey.GetValue("Path").ToString();
    var entries = key.Split(';'); //split into seperate paths.
    bool foundMatch = false;
	foreach (var item in entries)//Look if the desired path already exists
	{
        if(item == loc)
		{
            foundMatch = true;
            break;
		}
	}

    //If path is already there, don't make a duplicate.
	if (!foundMatch)
	{
        envKey.SetValue("Path", $"{key}{loc};");
    }
    
    //Tell windows to refresh
    SendNotifyMessage((IntPtr)HWND_BROADCAST, WM_SETTINGCHANGE, (UIntPtr)0, "Environment");

}
catch (Exception)
{

    throw;
}