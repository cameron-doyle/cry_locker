using System.Text;
using System.Security.Cryptography;
using Konscious.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Diagnostics;

namespace cry_locker
{
    class CryLocker
    {
        //Changing these will break old lockers
        private const int DegreeOfParallelism = 16;
        private const int MemorySize = 8192;
        private const int Iterations = 40;
        private const string Salt = "jhkbdshkjGBkfgaqwkbjk";

        private static Process explorer;
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
        public static double DataSizeConverter(double bytes)
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

		private static void OpenFolder(string path)
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
		}

		private static Aes GenerateKey(string password, HashConfig hc)
		{
            byte[]? pBytes = Encoding.ASCII.GetBytes(password);
            Argon2id? argon = new(pBytes);
            argon.DegreeOfParallelism = hc.DegreeOfParallelism;
            argon.MemorySize = hc.MemorySize;
            argon.Iterations = hc.Iterations;
            argon.Salt = hc.Salt;

            var key = argon.GetBytes(32);
            var iv = argon.GetBytes(16);

            //Empty ram after hash is generated
            argon = null;
            pBytes = null;
            GC.Collect();

            //Generate key
            var AES = Aes.Create();

            AES.Key = key;
            AES.IV = iv;
            AES.Mode = CipherMode.CBC;
            AES.Padding = PaddingMode.PKCS7;

            return AES;
        }

        /// <summary>
        /// Number of bytes (length of array)
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns>byte[]</returns>
        private static byte[] GenerateRandomBytes(int bytes = 32)
		{
            return RandomNumberGenerator.GetBytes(bytes);
        }

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
					Console.Write("Password:");
					string p1 = "";

					ConsoleKey k;
					do
					{
						var keyInfo = Console.ReadKey(true);
						k = keyInfo.Key;

						if (k == ConsoleKey.Backspace && p1.Length > 0)
						{
							Console.Write("\b \b");
							p1 = p1[0..^1];
						}
						else if (!char.IsControl(keyInfo.KeyChar))
						{
							Console.Write("*");
							p1 += keyInfo.KeyChar;
						}
					} while (k != ConsoleKey.Enter);

					p1 = p1.Trim();
					// Password Format 1 lower, upper, number, and symbol. Min 10 max 256
					if (p1 != null && Regex.IsMatch(p1, @"^(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[^\w\d\s:])([^\s]){10,256}$"))
					{
						Console.Clear();
						Console.Write("Confirm Password:");
						string? p2 = "";

						ConsoleKey k2;
						do
						{
							var keyInfo2 = Console.ReadKey(true);
							k2 = keyInfo2.Key;

							if (k2 == ConsoleKey.Backspace && p2.Length > 0)
							{
								Console.Write("\b \b");
								p2 = p2[0..^1];
							}
							else if (!char.IsControl(keyInfo2.KeyChar))
							{
								Console.Write("*");
								p2 += keyInfo2.KeyChar;
							}
						} while (k2 != ConsoleKey.Enter);

						p2 = p2?.Trim();
						if (p1 != null && p2 != null && p1 == p2)
						{
							//TODO change this
							password = p1;
							badPassword = false;
						}
						else
						{
							Console.Clear();
							Console.WriteLine("Passwords don't match, try again!\n");
						}
					}
					else
					{
						Console.Clear();
						Console.WriteLine("Passwords must contain 1 lower, upper, number and symbol with a minimum length of 10 (max 256)");
					}
				}

				Console.Clear();
                Console.WriteLine("Generating key...");

                //Setup locker
                Locker locker = new();

                //Setup config
                HashConfig hc = new(GenerateRandomBytes());

                //HashConfig hc = new();
                locker.LockerConfig = hc;
                locker.GenerateLocker(dir.FullName);
                locker.Key = GenerateKey(password, hc);

                //Begin encryption
                Console.CursorVisible = false; //Stops the cursor from flickering
                while (!DM.IsLoaded())
                {
                    Console.SetCursorPosition(0, Console.CursorTop);
                    Console.Write($"{GetLoading()} Discovering files...");
                    Thread.Sleep(250);
                }

                new Thread(() => DM.EncryptFiles(locker)).Start();

                //Wait for encryption
                Console.Clear();
                while (!DM.IsEncrypted())
                {
                    Console.SetCursorPosition(0, Console.CursorTop);
                    Console.Write($"{GetLoading()} Encrypted:{DM._encryptCount}/{DM.GetFiles().Count - DM._failed.Count}");
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
                    Console.WriteLine($"Attempted to encrypt {DM.GetFiles().Count} files, {DataSizeConverter(DM._root._size)} {DataSizePostFix(DM._root._size)} in {Math.Round(DM._encryptionTime >= 1000 ? DM._encryptionTime / 1000 : DM._encryptionTime)}{(DM._encryptionTime >= 1000 ? s : ms)}! ({DataSizeConverter(DM._root._size / (DM._encryptionTime / 1000))} {DataSizePostFix(DM._root._size / (DM._encryptionTime / 1000))}/s), however {DM._failed.Count} failed!\nFailed to encrypted:\n[");
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
                    Console.WriteLine($"Encrypted {DataSizeConverter(DM._root._size)} {DataSizePostFix(DM._root._size)} in {Math.Round(DM._encryptionTime >= 1000 ? DM._encryptionTime / 1000 : DM._encryptionTime)}{(DM._encryptionTime >= 1000 ? s : ms)}! ({DataSizeConverter(DM._root._size / (DM._encryptionTime / 1000))} {DataSizePostFix(DM._root._size / (DM._encryptionTime / 1000))}/s)");
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
                    Console.Write("Password:");
                    string password = "";

					ConsoleKey k;
					do
					{
						var keyInfo = Console.ReadKey(true);
						k = keyInfo.Key;

						if (k == ConsoleKey.Backspace && password.Length > 0)
						{
							Console.Write("\b \b");
							password = password[0..^1];
						}
						else if (!char.IsControl(keyInfo.KeyChar))
						{
							Console.Write("*");
							password += keyInfo.KeyChar;
						}
					} while (k != ConsoleKey.Enter);

					password = password.Trim();

					Console.Clear();
                    Console.WriteLine("Generating key...");

                    string name = Regex.Replace(file.FullName, "[.]cry_locker$", "_decrypted", RegexOptions.IgnoreCase);
                    DirManager.IsDecrypted = false;

                    //Setup locker
                    Locker locker = new(file);
                    locker.LoadConfig();
                    locker.Key = GenerateKey(password, locker.LockerConfig);
					if (locker.LoadManifest() == null)
					{
                        Console.Clear();
                        Console.WriteLine("Failed to load locker! Please check your password and try again!");
                        Console.WriteLine("Press any key to continue...");
                        Console.ReadKey();
                        return;
					}

                    //Setup output dir and start decrypt
                    var outputDir = Directory.CreateDirectory(name);
                    new Thread(() => DirManager.DecryptFiles(locker, outputDir)).Start();

                    Console.Clear();

                    Console.CursorVisible = false;
                    while (!DirManager.IsDecrypted)
                    {
                        Console.SetCursorPosition(0, Console.CursorTop);
                        Console.Write($"{GetLoading()} Decrypted:{DirManager.Decrypted}/{DirManager.ToDecrypt}");
                        Thread.Sleep(250);
                        if (DirManager.DecryptFailed && DirManager.DecryptFailReason != null)
                        {
                            Console.Clear();
                            Console.WriteLine("Decryption failed with reason:");
                            Console.WriteLine(DirManager.DecryptFailReason);
                            Console.WriteLine("Press any key to continue...");
                            outputDir.Delete(true);
                            Console.ReadKey();
                            break;
                        }
                    }
                    Console.CursorVisible = true;
                    Console.Clear();
                    OpenFolder(outputDir.FullName);
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
        
    }
}
