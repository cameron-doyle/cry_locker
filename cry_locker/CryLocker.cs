using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;
using System.Collections;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Threading;
using Konscious.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;

namespace cry_locker
{
    class CryLocker
    {
        //Changing these will break old lockers
        private const int DegreeOfParallelism = 16;
        private const int MemorySize = 8192;
        private const int Iterations = 40;
        private const string Salt = "jhkbdshkjGBkfgaqwkbjk";

        //private static Process explorer;
        static void Main(string[] args)
        {
            string loc = $"{Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)}";
            loc = new DirectoryInfo(loc).FullName;
            /*var token = Regex.Match(loc, "[%]user[%]", RegexOptions.IgnoreCase);
            if(token.Value.ToLower() == "%user%")
			{
                loc = Regex.Replace(loc, "[%]user[%]", Environment.UserName, RegexOptions.IgnoreCase);
			}*/

            Console.Clear();
            Console.WriteLine("===\nCry Locker\n===");

            while (true)
            {
				//string[] args = { "-e", "VSProjects/t" };
				bool continousExecution = false;
				if (args.Length == 0)
					continousExecution = true;

				string? cmd = "";
                string? path = "";

                Console.Write($"{loc}>");
                bool clear = false;
                string? input = null;
                input = input?.ToLower().Trim();

                //Argument check
                if (args.Length >= 2)
				{
                    cmd = GetCmd(args[0]);
                    path = args[1].Trim();
                }
                else
				{
                    input = Console.ReadLine();
                    cmd = GetCmd(input);
                    string? t_argument = GetArgument(input);
                    if (t_argument != null)
                        path = $"{loc}/{t_argument}";
                }



                /*					if (cmd == "cd")
                                    {
                                        //Navigating
                                        if (path != null)
                                        {
                                            DirectoryInfo test = new(path);
                                            if (test.Exists)
                                                loc = test.FullName;
                                        }else Console.WriteLine("Syntax error! cd requires a folder to navigate to.");
                                    }else

                                    if (cmd == "list")
                                    {
                                        DirectoryInfo dir = new(loc);
                                        foreach (var d in dir.GetDirectories())
                                        {
                                            Console.WriteLine(d.Name);
                                        }

                                        foreach (var f in dir.GetFiles())
                                        {
                                            Console.WriteLine(f.Name);
                                        }
                                    }else

                                    if (cmd == "clear")
                                    {
                                        clear = true;
                                    }else

                                    if (cmd == "help")
                                    {
                                        Console.WriteLine("" +
                                            "cd         navigate to directory.\n" +
                                            $"ls/dir    lists content of current working directory.\n" +
                                            $"clear     clears the terminal.\n" +
                                            "-e/encrypt encrypts selected folder.\n" +
                                            "-d/decrypt decrypts locker.\n" +
                                            "-a/add     add a file/folder to an existing locker.");
                                    }*/

                switch (cmd)
                {
                    case "encrypt":
                        Encrypt(path, true);
                        clear = true;
                        break;

                    case "decrypt":
                        Decrypt(path);
                        clear = true;
                        break;

                    case "help":
                        Console.WriteLine("" +
                            "cd         navigate to directory.\n" +
                            $"ls/dir    lists content of current working directory.\n" +
                            $"clear     clears the terminal.\n" +
                            "-e/encrypt encrypts selected folder.\n" +
                            "-d/decrypt decrypts locker.\n" +
                            "-a/add     add a file/folder to an existing locker.");
                        break;

                    case "clear":
                        clear = true;
                        break;

                    case "cd":
                        if (path != null)
                        {
                            DirectoryInfo test = new(path);
                            if (test.Exists)
                                loc = test.FullName;
                        }
                        else Console.WriteLine("Syntax error! cd requires a folder to navigate to.");
                        break;

                    case "list":
                        DirectoryInfo dir = new(loc);
                        foreach (var d in dir.GetDirectories())
                        {
                            Console.WriteLine(d.Name);
                        }

                        foreach (var f in dir.GetFiles())
                        {
                            Console.WriteLine(f.Name);
                        }
                        break;

                    default:
                        Console.WriteLine($"Command \"{cmd}\" is unrecognized! use -h to see a list of commands");
                        break;


                }

                //Terminal formatting
                Console.WriteLine("");
				if (clear)
				{
                    Console.Clear();
                    Console.WriteLine("===\nCry Locker\n===");
                }

                if (!continousExecution)
                    break;
            }
        }

        private static string? GetCmd(string? input)
        {
            try
            {
                string? t = input?.Trim();
                t = t?.Split(' ')[0].ToLower();

                switch (t)
				{
                    case "-e":
                        t = "encrypt";
                        break;
                    case "-d":
                        t = "decrypt";
                        break;
                    case "encrypt": break;
                    case "decrypt": break;
                    case "-h":
                        t = "help";
                        break;
                    case "help": break;
                    case "cd": break;
                    case "ls":
                        t = "list";
                        break;
                    case "dir":
                        t = "list";
                        break;
                    case "clear": break;
                    default:return null;
				}
                return t;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>
        /// Converts bytes to PB, TB, GB, MB, KB, B, all Rounded to 2 places.
        /// Can be used with dataSizePostFix() to get the postfix (i.e. GB)
        /// </summary>
        /// <param name="size">The value in bytes</param>
        /// <returns></returns>
        public static double dataSizeConverter(double bytes)
        {
            //{Math.Round(DM.Root.size > 1073741824 ? DM.Root.size / 1073741824 : DM.Root.size / 1048576, 2)} {(DM.Root.size > 1073741824 ? gb : mb)} in {Math.Round(DirManager.encryptionTime, 2)} seconds! ({Math.Round(((DM.Root.size / DirManager.encryptionTime) > 1073741824 ? DM.Root.size / 1073741824 : DM.Root.size / 1048576) / DirManager.encryptionTime)} {((DM.Root.size / DirManager.encryptionTime) > 1073741824 ? gb : mb)}/s)");
            if(bytes >= 1125899906842624)
            {
                //PB
                return Math.Round(bytes / 1125899906842624, 2);
            }
            else if(bytes >= 1099511627776)
            {
                //TB
                return Math.Round(bytes / 1099511627776, 2);
            }
            else if (bytes >= 1073741824)
            {
                //GB
                return Math.Round(bytes / 1073741824, 2);
            }
            else if (bytes >= 1048576)
            {
                //MB
                return Math.Round(bytes / 1048576, 2);
            }
            else if(bytes >= 1024)
            {
                //KB
                return Math.Round(bytes / 1024, 2);
            }
            else
            {
                //Bytes
                return Math.Round(bytes, 2);
            }
        }

        /// <summary>
        /// Returns the conversion post fix for a given bytes (to be used with dataSizeConverter())
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string DataSizePostFix(double bytes)
        {
            if (bytes >= 1125899906842624)
            {
                //PB
                return "PB";
            }
            else if (bytes >= 1099511627776)
            {
                //TB
                return "TB";
            }
            else if (bytes >= 1073741824)
            {
                //GB
                return "GB";
            }
            else if (bytes >= 1048576)
            {
                //MB
                return "MB";
            }
            else if (bytes >= 1024)
            {
                //KB
                return "KB";
            }
            else
            {
                //Bytes
                return "B";
            }
        }

        /// <summary>
        /// Scales a data transfer speed to seconds
        /// </summary>
        /// <returns></returns>
        public static double DataSpeedScaling(double bytes, double milliseconds)
        {
            //If over a second
            if(milliseconds >= 1000)
            {
                return bytes;
            }

            double scale = 1000 / milliseconds;
            return bytes * scale;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="input"></param>
        /// <param name="position">Gets the argument at a specified position (first argument is 1, second is 2, etc)</param>
        /// <returns></returns>
        private static string? GetArgument(string? input, int position = 1)
        {
            try
            {
                string? t = input?.Split(' ')[position];
                if(t?.Length <= 0 || t == "")
				{
                    return null;
				}
                return t;
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static string _icon = "|";
        private static string GetLoading()
        {
            switch (_icon)
            {
                case "|":
                    _icon = "/";
                    break;
                case "/":
                    _icon = "-";
                    break;
                case "-":
                    _icon = @"\";
                    break;
                case @"\":
                    _icon = "|";
                    break;
                default:
                    return _icon;
            }
            return _icon;
        }

        /*private static void OpenFolder(string path)
        {
            //string installLocation = @"C:\Users\Camer\Documents\VSProjects";
            string explorerPath = @"C:\Windows\explorer.exe";
            try
            {
                explorer = Process.Start(explorerPath, $"/root, {path}");
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }*/

/*        private static Config Setup()
        {
            return GetConfig();
        }*/


        private static void Encrypt(string path, bool isFolder)
		{
            DirectoryInfo? dir = null;
            FileInfo? file = null;
			if (isFolder)
			{
                dir = new(path);
			}else
			{
                file = new(path);
			}

            if ((dir != null && dir.Exists) || (file != null && file.Exists))
            {
                //Scan selected directory and sub dirs
                Console.Clear();
                Console.WriteLine("Discovering Files!...");
                DirManager DM = new(dir);

                //Ask for password
                Console.Clear();

                string password = "";

				bool badPassword = true;
				while (badPassword)
				{
					Console.WriteLine("Enter password");
					string? p1 = Console.ReadLine();
					p1 = p1?.Trim();
					Console.WriteLine("Confirm password");
					string? p2 = Console.ReadLine();
					p2 = p2?.Trim();
					if (p1 != null && p2 != null && p1 == p2)
					{
                        //TODO change this
                        password = "password";
						badPassword = false;
					}
					else
					{
						Console.Clear();
						Console.WriteLine("Passwords don't match, try again!\n");
					}
				}

                Console.Clear();
                Console.WriteLine("Generating key...");

                byte[]? pBytes = Encoding.ASCII.GetBytes(password);
                Argon2id? argon = new(pBytes);
                argon.DegreeOfParallelism = DegreeOfParallelism;
                argon.MemorySize = MemorySize;
                argon.Iterations = Iterations;
                argon.Salt = Encoding.ASCII.GetBytes(Salt);

                var key = argon.GetBytes(32);
                var iv = argon.GetBytes(16);

                //Empty ram after hash is generated
                argon = null;
                pBytes = null;
                GC.Collect();

				/*bool badPassword = true;
                while (badPassword)
                {
                    Console.WriteLine("Enter password");
                    p1 = Console.ReadLine();
                    p1 = p1.Trim();
                    Console.WriteLine("Confirm password");
                    string p2 = Console.ReadLine();
                    p2 = p2.Trim();
                    if (p1 == p2)
                    {
                        badPassword = false;
                    }
                    else
                    {
                        Console.Clear();
                        Console.WriteLine("Passwords don't match, try again!\n");
                    }
                }*/

				//Generate key
				//AesCryptoServiceProvider AES = new();
				var AES = Aes.Create();

                //https://stackoverflow.com/questions/61159825/password-as-key-for-aes-encryption-decryption
                //byte[] pw = new UnicodeEncoding().GetBytes(p1);

                AES.Key = key;
                AES.IV = iv;
                AES.Mode = CipherMode.CBC;
                AES.Padding = PaddingMode.PKCS7;

                DirManager.SetKey(AES);

                //Check for existing locker file and increment name
                string name = $"{dir}.cry_locker";
				int index = 0;
				while (new FileInfo(name).Exists)
				{
					index++;
					name = $"{dir}({index}).cry_locker";
				}

				try
				{
                    File.Create(name).Dispose(); //Closes stream
                }
                catch (Exception e)
				{
                    Console.WriteLine(e.Message);
                    return;
				}
                DirManager.SetLockerFile(new FileInfo(name));

                Console.CursorVisible = false;
                while (!DM.IsLoaded())
                {
                    Console.SetCursorPosition(0, Console.CursorTop);
                    Console.Write($"{GetLoading()} Discovering files...");
                    Thread.Sleep(250);
                }

                new Thread(DM.EncryptFiles).Start();

                //Wait for encryption
                Console.Clear();
                while (!DM.IsEncrypted())
                {
                    Console.SetCursorPosition(0, Console.CursorTop);
                    Console.Write($"{GetLoading()} Encrypted:{DM._encryptCount}/{DM.GetFiles().Count - DM._failed.Count}");
                    //Console.Write($" Failed:{DM._failed.Count}");
                    Thread.Sleep(250);
                }

                //Check hashing
                Console.Clear();
                while (!DM.IsHashed())
                {
                    Console.SetCursorPosition(0, Console.CursorTop);
                    Console.WriteLine($"{GetLoading()} Computing Hashes...");
                    Thread.Sleep(250);
                }
                Console.CursorVisible = true;

                //Check for failed items
                if (DM._failed.Count > 0)
                {
                    Console.Clear();
                    string ms = "ms";
                    string s = "s";
                    Console.WriteLine($"Attempted to encrypt {DM.GetFiles().Count} files, {dataSizeConverter(DM._root._size)} {DataSizePostFix(DM._root._size)} in {Math.Round(DM._encryptionTime >= 1000 ? DM._encryptionTime / 1000 : DM._encryptionTime)}{(DM._encryptionTime >= 1000 ? s : ms)}! ({dataSizeConverter(DM._root._size / (DM._encryptionTime / 1000))} {DataSizePostFix(DM._root._size / (DM._encryptionTime / 1000))}/s), however {DM._failed.Count} failed!\nFailed to encrypted:\n[");
                    //Console.WriteLine($"Encryption completed in {DirManager.encryptionTime}, with {DirManager.failed.Count} failures!\nFailed to encrypted:\n[");
                    foreach (FailedItem i in DM._failed)
                    {
                        Console.WriteLine($"{i._file._path}{i._file._name}");
                        Console.WriteLine($"\t{i._exception.Message}");
                    }
                    Console.WriteLine("]");
                }
                else
                {
                    Console.Clear();
                    string ms = "ms";
                    string s = "s";
                    Console.WriteLine($"Encrypted {dataSizeConverter(DM._root._size)} {DataSizePostFix(DM._root._size)} in {Math.Round(DM._encryptionTime >= 1000 ? DM._encryptionTime / 1000 : DM._encryptionTime)}{(DM._encryptionTime >= 1000 ? s : ms)}! ({dataSizeConverter(DM._root._size / (DM._encryptionTime / 1000))} {DataSizePostFix(DM._root._size / (DM._encryptionTime / 1000))}/s)");
                }
                GC.Collect();
                Console.WriteLine("Press any key to continue...");
                Console.ReadKey();

            }
            else
            {
                Console.WriteLine($"\"{dir.FullName}\" does not exit");
                Console.WriteLine("Press any key to continue...");
                Console.ReadKey();
            }
        }

        private static void Decrypt(string path)
		{
            Console.Clear();
            if (path != "" && path != null)
            {
                FileInfo file = new(path);

                if (file.Exists)
                {
                    //Ask for password
                    string password = "";

                    bool badPassword = true;
                    while (badPassword)
                    {
                        Console.WriteLine("Enter password");
                        string? p1 = Console.ReadLine();
                        p1 = p1?.Trim();
                        Console.WriteLine("Confirm password");
                        string? p2 = Console.ReadLine();
                        p2 = p2?.Trim();
                        if (p1 != null && p2 != null && p1 == p2)
                        {
                            //TODO change this
                            password = "password";
                            badPassword = false;
                        }
                        else
                        {
                            Console.Clear();
                            Console.WriteLine("Passwords don't match, try again!\n");
                        }
                    }

                    Console.Clear();
                    Console.WriteLine("Generating key...");

                    byte[] pBytes = Encoding.ASCII.GetBytes(password);
                    Argon2id argon = new(pBytes);
                    argon.DegreeOfParallelism = DegreeOfParallelism;
                    argon.MemorySize = MemorySize;
                    argon.Iterations = Iterations;
                    argon.Salt = Encoding.ASCII.GetBytes(Salt);

                    var key = argon.GetBytes(32);
                    var iv = argon.GetBytes(16);

                    //Empty ram after hash is generated
                    argon = null;
                    pBytes = null;
                    GC.Collect();

                    //Generate key
                    Aes AES = Aes.Create();

                    //https://stackoverflow.com/questions/61159825/password-as-key-for-aes-encryption-decryption
                    AES.Key = key;
                    AES.IV = iv;
                    AES.Mode = CipherMode.CBC;
                    AES.Padding = PaddingMode.PKCS7;

                    string name = Regex.Replace(file.FullName, "[.]cry_locker$", "", RegexOptions.IgnoreCase);
                    var output = Directory.CreateDirectory($"{name}_decrypted");
                    DirManager.SetLockerFile(file);
                    DirManager.SetDecryptFolder(output);
                    DirManager.SetKey(AES);
                    DirManager.IsDecrypted = false;
                    new Thread(DirManager.DecryptFiles).Start();

                    while (!DirManager.IsDecrypted)
                    {
                        Thread.Sleep(1000);
                        Console.Clear();
                        Console.WriteLine($"{GetLoading()} Decrypted:{DirManager.Decrypted}/{DirManager.ToDecrypt}");
                        if (DirManager.DecryptFailed)
                        {
                            Console.WriteLine("Decryption failed with reason:");
                            Console.WriteLine(DirManager.DecryptFailReason);
                            Console.WriteLine("Press any key to continue...");
                            Console.ReadKey();
                            break;
                        }
                    }

                    Console.Clear();
                    //OpenFolder(output.FullName);

                    //Setup decryption folder
                    /*DirManager.key = AES;
                    DirManager.EncryptFile = file;


                    DirManager.isDecrypted = false;
                    (new Thread(DirManager.DecryptFiles)).Start();

                    while (!DirManager.isDecrypted)
                    {
                        Thread.Sleep(1000);
                        Console.Clear();
                        Console.WriteLine($"{getLoading()} Decrypted:{DirManager.Decrypted}/{DirManager.ToDecrypt}");
                        if (DirManager.DecryptFailed)
                        {
                            Console.WriteLine("Decryption failed with reason:");
                            Console.WriteLine(DirManager.DecryptFailReason);
                            break;
                        }
                    }*/
                    //DirManager.loadFile(file);

                    /*Console.WriteLine("Press any key to continue...");
                    Console.ReadKey();*/

                }
                else
                {
                    Console.WriteLine($"File \"{path}\" doesn't exit");
                    Console.WriteLine("Press any key to continue...");
                    Console.ReadKey();
                }
            }
            else
            {
                Console.WriteLine("Path required!");
                Console.WriteLine("Press any key to continue...");
                Console.ReadKey();
            }



        }

        /*  private static string FilterOutDir(string line, string path)
          {
              var en = Encoding.Default;
              char[] chars = Encoding.Default.GetChars(Encoding.Default.GetBytes(line));

              string final = "";

              //Note we don't account for length to index conversion on i, because we have an extra character in the line as a seperater between path and cmd
              for (int i = path.Length; i < chars.Length; i++)
              {
                  final += chars[i];
              }
              return final;
          }*/

        /* private static Config GetConfig()
         {
             //string loc = System.Reflection.Assembly.GetExecutingAssembly().Location;
             string loc = AppContext.BaseDirectory;
             FileInfo exc = new(loc);
             FileInfo conf = new($"{exc.Directory.FullName}/config.json");
             if (conf.Exists)
             {
                 using FileStream fs = File.OpenRead(conf.FullName);
                 Config? result = JsonSerializer.Deserialize<Config>(fs);
                 if(result == null)
                 {
                     throw new Exception("Failed to load Config! Check if the syntax is valid...");
                 }
                 return result;
             }
             else
             {
                 var c = new Config("C:\\Users\\%USER%\\Documents", 2);
                 using FileStream fs = File.Create($"{exc.Directory.FullName}/config.json");
                 using StreamWriter sw = new(fs);
                 string t = JsonSerializer.Serialize(c);
                 Console.WriteLine(t);
                 sw.Write(t);
                 sw.Flush();

                 return c;
             }
         }*/
    }

   /* public class Config
	{
        public string DefaultPath { get; set; }
        public int Difficulty { get; set; }
        public string? DefaultSaveLocation { get; set; }
        public Config(string DefaultPath, int Difficulty, string? DefaultSaveLocation = null)
		{
            this.DefaultPath = DefaultPath;
            this.Difficulty = Difficulty;
            this.DefaultSaveLocation = DefaultSaveLocation;
		}
	}*/
}
