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


namespace cry_locker
{
    class CryLocker
    {
        private static Process explorer;
        static void Main(string[] args)
        {
            bool _exit = false;
            while (!_exit)
            {
                //TODO fix password
                //TODO encrypt manifest
                Console.Clear();
                Console.WriteLine("######\nCry Locker\n######");
                string input = Console.ReadLine();
                input = input.ToLower().Trim();
                string cmd = getCmd(input);
                string path = getArgument(input);
                switch (cmd)
                {
                    #region create
                    case "encrypt":
                        if (path != "" && path != null)
                        {

                            //FileInfo file = new FileInfo($"C:\\Users\\Camer\\Documents\\VSProjects");
                            //DirectoryInfo dir = new DirectoryInfo($"D:\\{path}");
                            DirectoryInfo dir = new DirectoryInfo($"C:\\Users\\Camer\\Documents\\VSProjects\\{path}");

                            if (dir.Exists)
                            {
                                //Scan selected directory and sub dirs
                                Console.Clear();
                                Console.WriteLine("Discovering Files!...");
                                DirManager DM = new DirManager(dir);

                                //Ask for password
                                string p1 = "password";
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
                                AesCryptoServiceProvider key = new AesCryptoServiceProvider();

                                //https://stackoverflow.com/questions/61159825/password-as-key-for-aes-encryption-decryption
                                byte[] pw = new UnicodeEncoding().GetBytes(p1);

                                key.Key = SHA256.Create().ComputeHash(pw);
                                key.IV = MD5.Create().ComputeHash(pw);
                                key.Mode = CipherMode.CBC;
                                key.Padding = PaddingMode.PKCS7;

                                DirManager.SetKey(key);

                                //Check for existing locker file and increment name
                                string name = $"{dir}.cry";
                                /*int index = 0;
                                while(new FileInfo(name).Exists)
                                {
                                    index++;
                                    name = $"{dir}({index}).cry";
                                }*/

                                (File.Create(name)).Dispose(); //Closes stream
                                DirManager.SetLockerFile(new FileInfo(name));


                                while (!DM.IsLoaded())
                                {
                                    Thread.Sleep(1000);
                                    Console.Clear();
                                    Console.WriteLine($"{getLoading()} Discovering files!");
                                }

                                new Thread(DM.EncryptFiles).Start();
                                
                                //Wait for encryption
                                while (!DM.IsEncrypted())
                                {
                                    Console.Clear();
                                    Console.WriteLine($"{getLoading()} Encrypted:{DM._encryptCount}/{DM.GetFiles().Count - DM._failed.Count}\n  Failed:{DM._failed.Count}");
                                    Thread.Sleep(1000);
                                }

                                //Check hashing
                                while (!DM.IsHashed())
                                {
                                    Thread.Sleep(1000);
                                    Console.Clear();
                                    Console.WriteLine($"{getLoading()} Computing Hashes!");
                                }

                                /*Manifest man = DM.GenerateManifest();
                                man.WriteToDisk();*/

                                //Console.WriteLine(man.Serialize());
                                //Console.ReadLine();

                                /*Console.Clear();
                                Console.WriteLine("Compiling...");
                                DM.CompileFile();
                                Console.ReadLine();*/


                                //Check for failed items
                                if (DM._failed.Count > 0)
                                {
                                    Console.Clear();
                                    string ms = "ms";
                                    string s = "s";
                                    Console.WriteLine($"Attempted to encrypt {DM.GetFiles().Count} files, {dataSizeConverter(DM._root._size)} {dataSizePostFix(DM._root._size)} in {Math.Round(DM._encryptionTime >= 1000 ? DM._encryptionTime / 1000 : DM._encryptionTime)}{(DM._encryptionTime >= 1000 ? s : ms)}! ({dataSizeConverter(DM._root._size / (DM._encryptionTime / 1000))} {dataSizePostFix(DM._root._size / (DM._encryptionTime / 1000))}/s), however {DM._failed.Count} failed!\nFailed to encrypted:\n[");
                                    //Console.WriteLine($"Encryption completed in {DirManager.encryptionTime}, with {DirManager.failed.Count} failures!\nFailed to encrypted:\n[");
                                    foreach(FailedItem i in DM._failed)
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
                                    Console.WriteLine($"Encrypted {dataSizeConverter(DM._root._size)} {dataSizePostFix(DM._root._size)} in {Math.Round(DM._encryptionTime >= 1000 ? DM._encryptionTime / 1000 : DM._encryptionTime)}{(DM._encryptionTime >= 1000 ? s : ms)}! ({dataSizeConverter(DM._root._size / (DM._encryptionTime / 1000))} {dataSizePostFix(DM._root._size / (DM._encryptionTime / 1000))}/s)");
                                }
                                GC.Collect();
                                Console.WriteLine("Press any key to continue...");
                                Console.ReadKey();

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
                        break;
                    #endregion
                    #region open
                    case "decrypt":
                        /*
                         * Get password
                         * Generate key
                         * Decrypt manifest
                         * if decrypts move on
                         * rename files and folders from uuid to names
                         * ask which files/folder/all to decrypt
                         * save files to a temp folder 
                         * on close, check for files changes and resave
                         */
                        if (path != "" && path != null)
                        {

                            //FileInfo file = new FileInfo($"C:\\Users\\Camer\\Documents\\VSProjects");
                            //DirectoryInfo dir = new DirectoryInfo($"D:\\{path}");
                            FileInfo file = new FileInfo($"C:\\Users\\Camer\\Documents\\VSProjects\\{path}.cry");

                            if (file.Exists)
                            {
                                //Scan selected directory and sub dirs
                                Console.Clear();

                                //Ask for password
                                string p1 = "password";
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
                                AesCryptoServiceProvider key = new AesCryptoServiceProvider();

                                //https://stackoverflow.com/questions/61159825/password-as-key-for-aes-encryption-decryption
                                byte[] pw = new UnicodeEncoding().GetBytes(p1);

                                key.Key = SHA256.Create().ComputeHash(pw);
                                key.IV = MD5.Create().ComputeHash(pw);
                                key.Mode = CipherMode.CBC;
                                key.Padding = PaddingMode.PKCS7;

                                var output = Directory.CreateDirectory($"{file.FullName.Remove(file.FullName.Length - 4, 4)}_decrypted");
                                DirManager.SetLockerFile(file);
                                DirManager.SetDecryptFolder(output);
                                DirManager.SetKey(key);
                                DirManager.IsDecrypted = false;
                                new Thread(DirManager.DecryptFiles).Start();

                                while (!DirManager.IsDecrypted)
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
                                }

                                Console.Clear();
                                openFolder(output.FullName);

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



                        break;
                    #endregion
                    case "test":

                        break;
                    default:
                        Console.WriteLine($"Command \"{cmd}\" is unrecognized!");
                        break;

                }
            }
        }

        private static string getCmd(string input)
        {
            try
            {
                return input.Split(' ')[0];
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
        public static string dataSizePostFix(double bytes)
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
        public static double dataSpeedScaling(double bytes, double milliseconds)
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
        private static string getArgument(string input, int position = 1)
        {
            try
            {
                return input.Split(' ')[position];
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static string _icon = "|";
        private static string getLoading()
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

        private static void openFolder(string path)
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

        public void deleteTemp()
        {
            explorer.CloseMainWindow();
            //TODO delete temp folder
            //DirectoryInfo temp_dir = new DirectoryInfo(temp_folder_location);
            //temp_dir.Delete(true);
            Console.WriteLine("Deleted temp folder");
            Console.ReadLine();
        }
    }
}
