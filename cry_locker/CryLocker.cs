using System.Text;
using System.Security.Cryptography;
using Konscious.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Reflection;

namespace cry_locker
{
    class CryLocker
    {
        //Changing these will break old lockers
        //private const int DegreeOfParallelism = 16;
        //private const int MemorySize = 8192;
        //private const int Iterations = 40;
        //private const string Salt = "jhkbdshkjGBkfgaqwkbjk";

        private static Process? explorer;
        public const string extention = "cry_locker";
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

            /*var p = System.IO.Directory.GetCurrentDirectory();

            Console.WriteLine(p);

            foreach (var item in args)
            {
                Console.WriteLine(item);
            }
            Console.ReadLine();*/
            /*while (true)
            {*/
				//string[] args = { "-e", "VSProjects/t" };
				//bool continousExecution = false;
				/*if (args.Length == 0)
					continousExecution = true;*/

				string? cmd = "";
                string? path = "";

            //Console.Write($"{loc}>");
            //bool clear = false;
            //string? input = null;
            //input = input?.ToLower().Trim();

            //Argument check
            /*if (args.Length == 1)
            {
                var s = args[0];
                var file = new FileInfo(s);
                var file2 = new FileInfo($"{System.IO.Directory.GetCurrentDirectory()}/{s}");

                Console.WriteLine(file2.FullName);
                Console.ReadLine();
                return;
                return;
                if (file.Exists)
                {
                    cmd = "encrypt";
                    path = file.FullName;
                }else if (file2.Exists)
                {
                    cmd = "encrypt";
                    path = file2.FullName;
                }
                else
                {
                    Console.Clear();
                    Console.WriteLine($"File '{s}' does not exist!");
                    Console.WriteLine("Press any key to continue...");
                    Console.ReadKey();
                }
            }
            else */
            List<string> t_args = new();
            //t_args.Add("-h");
            //t_args.Add(@"C:\Users\Camer\test");
            //t_args.Add(@"C:\Users\Camer\test\tfile.mkv");
            //t_args.Add(@"C:\Users\Camer\test.cry_locker");
            t_args.Add(@"C:\Users\Camer\test\tfile.cry_locker");
            if (t_args.Count == 1)
			{
				switch (EvalAction(t_args[0]))
				{
                    case EvalType.decrypt:
                        cmd = "decrypt";
                        path = t_args[0];
                        break;
                    case EvalType.encrypt_dir:
                        cmd = "encrypt";
                        path = t_args[0];
                        break;
                    case EvalType.encrypt_file:
                        cmd = "encrypt";
                        path = t_args[0];
                        break;
                }

                //path = t_args[1].Trim();
                //var item = new FileInfo(path);

                //Check for relative or full path
                /*if (!item.Exists)
                {
                    item = new FileInfo($"{System.IO.Directory.GetCurrentDirectory()}/{path}");
                    if (item.Exists)
                    {
                        path = item.FullName;
                    }
                }
                Console.WriteLine(path);*/
            }
            else if(t_args.Count >= 2)
			{
                cmd = t_args[0];
                path = t_args[1];
            }
				/*else
				{
					input = Console.ReadLine();
					cmd = GetCmd(input);
					string? t_argument = GetArgument(input);
					if (t_argument != null)
						path = $"{loc}/{t_argument}";
				}*/

			switch (cmd)
            {
                case "encrypt":
                    Encrypt(path);
                    break;

                case "decrypt":
                    Decrypt(path);
                    //clear = true;
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

                default:
                    Console.WriteLine($"Syntax invalid! use -h to see a list of commands");
                    break;


            }

                //Terminal formatting
                /*Console.WriteLine("");
				if (clear)
				{
                    Console.Clear();
                    Console.WriteLine("===\nCry Locker\n===");
                }

                if (!continousExecution)
                    break;*/
            //}
        }

        private enum EvalType
		{
            decrypt,
            encrypt_file,
            encrypt_dir
		}

        private static EvalType? EvalAction(string path)
		{
            //Figure out if dir and file
            if (File.Exists(path) || Directory.Exists(path))
            {
                FileAttributes attr = File.GetAttributes(path);
                if ((attr & FileAttributes.Directory) == FileAttributes.Directory)
                {
                    if (Directory.Exists(path))
                        return EvalType.encrypt_dir;
                }
                else
                {
                    var f = new FileInfo(path);
                    if (f.Exists && f.Extension == $".{extention}")
                    {
                        return EvalType.decrypt;
                    }
                    else if (f.Exists)
                    {
                        return EvalType.encrypt_file;
                    }
                }
            }
            return null;
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
        public static long DataSizeConverter(long bytes)
        {
            //{Math.Round(DM.Root.size > 1073741824 ? DM.Root.size / 1073741824 : DM.Root.size / 1048576, 2)} {(DM.Root.size > 1073741824 ? gb : mb)} in {Math.Round(DirManager.encryptionTime, 2)} seconds! ({Math.Round(((DM.Root.size / DirManager.encryptionTime) > 1073741824 ? DM.Root.size / 1073741824 : DM.Root.size / 1048576) / DirManager.encryptionTime)} {((DM.Root.size / DirManager.encryptionTime) > 1073741824 ? gb : mb)}/s)");
            if(bytes >= 1125899906842624)
            {
                //PB
                return bytes / 1125899906842624;
            }
            else if(bytes >= 1099511627776)
            {
                //TB
                return bytes / 1099511627776;
            }
            else if (bytes >= 1073741824)
            {
                //GB
                return bytes / 1073741824;
            }
            else if (bytes >= 1048576)
            {
                //MB
                return bytes / 1048576;
            }
            else if(bytes >= 1024)
            {
                //KB
                return bytes / 1024;
            }
            else
            {
                //Bytes
                return bytes;
            }
        }

        /// <summary>
        /// Returns the conversion post fix for a given bytes (to be used with dataSizeConverter())
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string DataSizePostFix(long bytes)
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

        private static void Encrypt(string path)
        {
            bool isFolder = false;
            //DirectoryInfo? dir = null;
            //FileInfo? file = null;

            var type = EvalAction(path);

            if (type == EvalType.encrypt_dir || type == EvalType.encrypt_file)
            {
                if (type == EvalType.encrypt_dir)
                    isFolder = true;

                //Scan selected directory and sub dirs
                Console.Clear();
                Console.WriteLine("Discovering Files!...");
                
                DirManager DM;
                //Setup locker
                Locker locker = new();
                HashConfig hc = new(isFolder, GenerateRandomBytes());
                locker.LockerConfig = hc;
                if (isFolder)
                {
                    var dir = new DirectoryInfo(path);
                    locker.GenerateLocker(dir.FullName);
                    DM = new(dir);
                }
                else
                {
                    var file = new FileInfo(path);
                    locker.GenerateLocker(file.FullName);
                    DM = new(file);
                }

				//Ask for password
				#region Password
				Console.Clear();

                string password = "";
				bool badPassword = true;
                Console.CursorVisible = true;
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
					if (p1 != null && Regex.IsMatch(p1, @"^(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[^A-Za-z0-9])([^\s]){10,256}$"))
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
				#endregion

				Console.Clear();
                Console.CursorVisible = false;
                Console.WriteLine("Generating key...");

                

                //Setup config
                
                //locker.GenerateLocker((isFolder) ? dir.FullName:file.FullName);
                locker.Key = GenerateKey(password, hc);

                //Clear password from RAM
                password = null;
                GC.Collect();

                //Begin encryption

                while (!DM.IsLoaded())
                {
                    Console.SetCursorPosition(0, Console.CursorTop);
                    Console.Write($"{GetLoading()} Discovering file(s)...");
                    Thread.Sleep(250);
                }

                new Thread(() => DM.Encrypt(locker)).Start();

                //Wait for encryption
                Console.Clear();
                while (!DM.IsEncrypted())
                {
                    Console.SetCursorPosition(0, Console.CursorTop);
                    var fi = new FileInfo(locker.LockerFile.FullName);
                    Console.Write($"{GetLoading()} Encrypting: {Math.Round(((decimal)fi.Length / (decimal)DM._totalBytes) * 100, 2)}%");
                    Thread.Sleep(250);
                }
				

                //Check hashing
                Console.Clear();
                /*while (!DM.IsHashed())
                {
                    Console.SetCursorPosition(0, Console.CursorTop);
                    Console.WriteLine($"{GetLoading()} Computing Hashes...");
                    Thread.Sleep(250);
                }*/


                var failed = DM._failed;
                var total = DM.GetFileCount();
                var size = DM._totalBytes;
                var encryptionTime = DM._encryptionTime;
                locker = null;
                DM = null;
                GC.Collect();

                //Check for failed items
                if (failed.Count > 0)
                {
                    Console.Clear();
                    string ms = "ms";
                    string s = "s";
                    foreach (var f in failed)
                    {
                        Console.WriteLine($"\n{f._file._path}{f._file._name}");
                        Console.WriteLine(f._exception.Message);
                    }
                    Console.WriteLine($"\nAttempted to encrypt {total} file(s), {DataSizeConverter(size)} {DataSizePostFix(size)} in {Math.Round(encryptionTime >= 1000 ? encryptionTime / 1000 : encryptionTime)}{(encryptionTime >= 1000 ? s : ms)}! ({DataSizeConverter((long)(size / (encryptionTime / 1000)))} {DataSizePostFix((long)(size / (encryptionTime / 1000)))}/s), however {failed.Count} failed!");
                }
                else
                {
                    Console.Clear();
                    string ms = "ms";
                    string s = "s";
                    Console.WriteLine($"Encrypted {DataSizeConverter(size)} {DataSizePostFix(size)} in {Math.Round(encryptionTime >= 1000 ? encryptionTime / 1000 : encryptionTime)}{(encryptionTime >= 1000 ? s : ms)}! ({DataSizeConverter((long)(size / (encryptionTime / 1000)))} {DataSizePostFix((long)(size / (encryptionTime / 1000)))}/s)");
                }

                GC.Collect();
                Console.CursorVisible = true;
                Console.WriteLine("Press any key to continue...");
                Console.ReadKey();

            }
			else
			{
				Console.WriteLine($"\"{path}\" does not exit. Please try again.");
				Console.WriteLine("Press any key to continue...");
				Console.ReadKey();
			}
		}

        private static void Decrypt(string path)
		{
            Console.Clear();
            //DirectoryInfo? dir = null;
            //FileInfo? file = null;

			if (EvalAction(path) == EvalType.decrypt)
            {
                FileInfo file = new(path);

				//Ask for password
				#region password
				Console.Write("Password:");
                    string password = "AnnieCamTess1231@";

					/*ConsoleKey k;
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

					password = password.Trim();*/
				#endregion

				Console.Clear();
                Console.WriteLine("Generating key...");

                    
                DirManager.IsDecrypted = false;



                //Setup locker
                Locker locker = new(file);

                locker.LoadConfig();
                locker.Key = GenerateKey(password, locker.LockerConfig);
                if (locker.LockerConfig.IsArchive)
                {
                    if (locker.LoadManifest() == null)
                    {
                        Console.Clear();
                        Console.WriteLine("Failed to load locker! Please check your password and try again!");
                        Console.WriteLine("Press any key to continue...");
                        Console.ReadKey();
                        return;
                    }
                }

                string name = Regex.Replace(file.FullName, $"[.]{extention}$", "", RegexOptions.IgnoreCase);
                int index = 0;
                while (File.Exists(name) || Directory.Exists(name))
                {
                    index++;
                    if (index <= 1)
                        name = Regex.Replace(file.FullName, $"[.]{extention}$", "_decrypted", RegexOptions.IgnoreCase);
                    else name = Regex.Replace(file.FullName, $"[.]{extention}$", $"_decrypted({index})", RegexOptions.IgnoreCase);
                }


                //Setup output dir and start decrypt
                DirectoryInfo? outputDir = null;
                if (locker.LockerConfig.IsArchive)
                    outputDir = Directory.CreateDirectory(name);
                new Thread(() => DirManager.DecryptFiles(locker, name)).Start();

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
                        if (outputDir != null)
                            outputDir.Delete(true);
                        Console.ReadKey();
                        break;
                    }
                }
                Console.CursorVisible = true;
                Console.Clear();

                if(outputDir != null)
                    OpenFolder(outputDir.FullName);
            }
            else
            {
                Console.WriteLine($"File \"{path}\" doesn't exit or is not a locker, please try again.");
                Console.WriteLine("Press any key to continue...");
                Console.ReadKey();
            }
        }
        
    }
}
