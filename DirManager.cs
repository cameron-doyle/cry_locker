using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using Newtonsoft.Json;
using System.Threading;
using Force.Crc32;
using System.Runtime.Caching;
using System.Diagnostics;
//using System.IO.Stream;

public class DirManager
{
	public Dir Root { get; private set; }
	public static FileInfo EncryptFile { private get; set; }
	public static DirectoryInfo DecryptFolder { private get; set; }
	public static AesCryptoServiceProvider key { private get; set; }
	private bool _isEncrypted = false;

	public DirManager(DirectoryInfo root, FileInfo encryptFile = null, AesCryptoServiceProvider encryptionKey = null)
	{
		//DirManager.maxRam = maxRam * 1048576;
		EncryptFile = encryptFile;
		key = encryptionKey;
		Root = new Dir(root);
	}

	public bool isLoaded()
	{
		return Root.isLoaded();
	}

	public bool isHashed()
    {
		return Root.isHashed();
    }

	public List<OurFile> getFiles()
	{
		return Root.getFiles();
	}

	public static AesCryptoServiceProvider getKey()
	{
		if (key == null)
			throw new NullReferenceException("Key was never set!");
		return key;
	}

	public static FileInfo getEncryptFile()
	{
		if (EncryptFile == null)
			throw new NullReferenceException("SaveLocation was never set!");
		return EncryptFile;
	}

	public static int encryptCount = 0;
	public static double encryptionTime { get; private set; }
	public static List<FailedItem> failed = new List<FailedItem>();
	public void EncryptFiles(Object stateInfo)
    {
		//Reset vars
		encryptCount = 0;
		failed = new List<FailedItem>();

		List<OurFile> files = Root.getFiles();

		//Time encryption
		Stopwatch sw = new Stopwatch();
		sw.Start();

		foreach(OurFile f in files)
        {
			f.Encrypt();
        }

		sw.Stop();
		encryptionTime = sw.Elapsed.TotalMilliseconds;

        _isEncrypted = true;
	}

	public static int Decrypted = 0;
	public static int ToDecrypt = 0;
	public static bool isDecrypted = false;
	public static bool DecryptFailed = false;
	public static string DecryptFailReason = null;
	public static void DecryptFiles()
    {
		isDecrypted = false;
		Decrypted = 0;
		DecryptFailed = false;
		DecryptFailReason = null;
		List<LockerFile> lockerInfo = getLockerFileInfo(getEncryptFile());
		ToDecrypt = lockerInfo.Count - 1;
		LockerFile manifestInfo = null;
        foreach (LockerFile lf in lockerInfo)
        {
			if(lf.name == "manifest")
            {
				manifestInfo = lf;
				lockerInfo.Remove(lf);
				break;
            }
        }

		if(manifestInfo == null)
        {
			DecryptFailReason = "Manifest file missing, locker is likely corrupt!";
			DecryptFailed = true;
			return;
        }

		//Decrypt manifest
		Manifest manifest = loadManifest(getEncryptFile(), key, manifestInfo);

		//Decrypt files
		foreach(LockerFile lf in lockerInfo)
        {
			ManifestItem manifestItem = manifest.getItem(lf.name);
			string path = $"{DecryptFolder.FullName}{manifestItem.Path}";

			//Create folders required for path
			Directory.CreateDirectory(path);

			using (FileStream fReader = File.OpenRead(getEncryptFile().FullName))
			{
				using (FileStream fWriter = File.Create($"{path}{manifestItem.Name}"))
				{
					using (CryptoStream cs = new CryptoStream(fWriter, key.CreateDecryptor(), CryptoStreamMode.Write))
					{
						//Seek to starting byte
						fReader.Seek(lf.startIndex, SeekOrigin.Begin);
						//Loop through desired bytes, decrypt then write.
						for (int i = 0; i < lf.endIndex - lf.startIndex; i++)
						{
							cs.WriteByte((byte)fReader.ReadByte());
						}
					}
                }
			}
			Decrypted++;
		}
		isDecrypted = true;
	}

	private static Manifest loadManifest(FileInfo locker, AesCryptoServiceProvider key, LockerFile info)
    {
		using(FileStream fs = File.OpenRead(locker.FullName))
        {
			using (BinaryReader br = new BinaryReader(fs))
			{
				byte[] buffer = new byte[(info.endIndex - info.startIndex)];

				fs.Seek(info.startIndex, SeekOrigin.Begin);
				br.Read(buffer, 0, info.endIndex - info.startIndex);
				using (MemoryStream ms = new MemoryStream(buffer))
				{
					using (CryptoStream cs = new CryptoStream(ms, key.CreateDecryptor(), CryptoStreamMode.Read))
					{
						buffer = new byte[ms.Length];
						using (StreamReader sr = new StreamReader(cs))
                        {
							return Manifest.Deserialize(sr.ReadToEnd());
						}

					}
				}
			}
			
        }
    }

	private static List<LockerFile> getLockerFileInfo(FileInfo locker)
	{
		//TODO optimise this method
		List<LockerFile> lockerFiles = new List<LockerFile>();
		using (FileStream fs = File.OpenRead(locker.FullName))
		{
			using(BufferedStream buff = new BufferedStream(fs))
			{
				using (BinaryReader bn = new BinaryReader(buff))
				{
					
					string pattern = "[beginFile:";
					int length = pattern.Length;
					byte[] bytes = new byte[length];
					int startIndex = -1;
					string name = "";
					bool readingHeader = false;
					for (int i = 0; i <= fs.Length; i++)
					{
						//Shift bytes left
						bytes = shiftLeft(bytes);

						//Read data to array
                        try {
							//Write byte to last element because of shifting to left.
							bytes[10] = bn.ReadByte();
						} catch (EndOfStreamException e) {
							//End of file
							var lf = new LockerFile(startIndex, (int)fs.Length, name);
							lockerFiles.Add(lf);
							break; //Probably don't need to break here, but it saves time not having to go through header management
						}


						#region header management
						//Check for header pattern
						if (Encoding.Default.GetString(bytes).StartsWith(pattern))
						{
							readingHeader = true;
							
							//Previous header was found, record end of file data.
							if (startIndex >= 0)
							{
								var lf = new LockerFile(startIndex, i - 10, name);
								lockerFiles.Add(lf);
								startIndex = -1;
								name = "";
							}
						}
						else if (readingHeader)
						{
							if (Encoding.Default.GetString(bytes).EndsWith("]"))
							{
								//Check for end header symbol
								readingHeader = false;
								startIndex = i + 1;
							}
							else
							{
								//Else, still reading name
								name += Encoding.Default.GetString(bytes, 10, 1);
							}
						}
                        #endregion
                    }
                }
				
			}
		}
		return lockerFiles;
	}

	private static byte[] shiftLeft(byte[] input)
	{
		byte[] shifted = new byte[input.Length];
		for (int i = 0; i < input.Length; i++)/*minus 1 for length to index, another because we don't want the last value of input*/
		{
			shifted[i] = input[(i + 1) % input.Length];
		}
		return shifted;
	}

	public void CompileFile()
	{
		/*string inputDirectoryPath = SaveLocation.FullName;
		string outputFilePath = $"{SaveLocation.Parent.FullName}\\{Root.self.Name}.cry";
		
		//Overly complicated way of loading manifest first
		string[] temp = Directory.GetFiles(inputDirectoryPath, "*.cry_item");
		string[] temp_manifest = Directory.GetFiles(inputDirectoryPath, "manifest");
		string[] inputFilePaths = new string[temp.Length + temp_manifest.Length];
		temp_manifest.CopyTo(inputFilePaths, 0);
		temp.CopyTo(inputFilePaths, temp_manifest.Length);
		Console.WriteLine("Number of files: {0}.", inputFilePaths.Length);
		using (var outputStream = File.Create(outputFilePath))
		{
			foreach (var inputFilePath in inputFilePaths)
			{
				FileInfo file = new FileInfo(inputFilePath);
				using (var inputStream = File.OpenRead(inputFilePath))
				{
					using (BufferedStream bf = new BufferedStream(inputStream))
					{

						// Buffer size can be passed as the second argument.



						StreamWriter sw = new StreamWriter(outputStream);
						//Remove extension from name unless manifest
						sw.Write($"[begin]:[{(file.Name == "manifest" ? file.Name : file.Name.Remove(file.Name.Length - 9, 9))}]");
						sw.Flush();
						outputStream.Seek(0, SeekOrigin.End);
						inputStream.CopyTo(outputStream);
					}
				}
				Console.WriteLine("The file {0} has been processed.", inputFilePath);
			}
		}*/
	}

	public static void loadFile(FileInfo path)
    {
        
		using (var inputStream = File.OpenRead(path.FullName))
        {
			StreamReader sr = new StreamReader(inputStream);
			Console.WriteLine("File contents...");
			Console.WriteLine(sr.ReadToEnd());
			Console.ReadLine();
        }
    }

	public void GenerateHash()
    {
		foreach (OurFile f in Root.getFiles())
        {
			f.ComputeHash();
        }
    }

	public bool isEncrypted()
    {
		return _isEncrypted;
    }



	/// <summary>
	/// Generates a Manfest file and if saveLocation is set, saves to file inside of locker
	/// </summary>
	/// <returns></returns>
	public Manifest generateManifest()
    {
		List<OurFile> files = getFiles();
		Manifest m = new Manifest();
		foreach(OurFile f in files)
        {
            if (!f.isComputed)
            {
				throw new Exception("All file hashes must be computed before generating manifest!");
            }
			m.Add(new ManifestItem(f.path, f.hash, f.name, f.uuid));
        }

		return m;
    }

	/// <summary>
	/// Determines weather there is enough ram to load a given file, files that are larger than the maxRam limit, will only be allowed if there are no other files currently loaded.
	/// </summary>
	/// <returns></returns>
/*	private static List<FileInfo> filesLoaded;
	private static long ramUsage = 0;
	private static int maxRam; //MB (already converted down to bytes by constructor)
	public static bool requestLoad(FileInfo file)
    {
		if ((file.Length + ramUsage) <= maxRam)
		{
			filesLoaded.Add(file);
			ramUsage += file.Length;
			return true;
		}
		return false;
    }*/

	/// <summary>
	/// Notifies the ramManagement system that a file has been unloaded from ram
	/// </summary>
	/// <param name="file"></param>
/*	public static void unloadFile(FileInfo file)
    {
		filesLoaded.Remove(file);
		ramUsage -= file.Length;
    }*/

	
}

public class Dir
{
	private Dir parent; //If null, it signified it's the root
	public DirectoryInfo self { get; private set; }
	private List<Dir> subDirs = new List<Dir>();
	private List<OurFile> files = new List<OurFile>();
	private bool filesLoaded = false;
	private bool subDirsLoaded = false;
	public double size { get; private set; }

    public Dir(DirectoryInfo dir, Dir parent = null)
    {
		this.parent = parent;
		self = dir;
		size = 0;

		foreach(DirectoryInfo d in dir.GetDirectories())
        {
			Dir subD = new Dir(d, this);
			subDirs.Add(subD);
			size += subD.size;
        }
		subDirsLoaded = true;

		foreach (FileInfo f in dir.GetFiles())
		{
			size += f.Length;
			var nf = new OurFile(f, this);
			files.Add(nf);
		}

		//Compute check
        /*while (true)
        {
			foreach (OurFile f in _nonComputed)
			{
				if (f.isComputed)
				{
					_nonComputed.Remove(f);
					break;
				}

			}
			if(_nonComputed.Count <= 0)
            {
				break;
            }
			Thread.Sleep(250);
		}*/
		filesLoaded = true;

/*		while (!filesLoaded)
        {
			filesLoaded = true;
			foreach(File f in files)
            {
				if (!f.isComputed)
                {
					filesLoaded = false;
					break;
				}
            }
			//Thread.Sleep(250);
        }*/
	}

	public bool isLoaded()
    {
		if (filesLoaded && subDirsLoaded)
			return true;
		return false;
    }

	public void BeginHash()
    {
		foreach(OurFile f in files)
        {
			f.ComputeHash();
        }
    }

	public bool isHashed()
    {
		foreach(OurFile f in getFiles())
        {
			if (!f.isComputed)
				return false;
        }
		return true;
    }

	public List<OurFile> getFiles()
    {
		List<OurFile> temp = new List<OurFile>();
		foreach(Dir d in subDirs)
        {
			foreach(OurFile f in d.getFiles())
            {
				temp.Add(f);
            }
        }

		foreach(OurFile f in files)
        {
			temp.Add(f);
        }

		return temp;
    }

	public string getLocalPath()
    {
		if(parent != null)
        {
			return $"{parent.getLocalPath()}{self.Name}/";
        }
        else
        {
			//Is root
			return $"/";
        }
    }
}

public class OurFile
{
	public FileInfo info { get; private set; }
	//private byte[] fileContent;
	private Dir parent;
	public string hash { get; private set; }
	public string path { get; private set; }
	public string name { get; private set; }
	public string uuid { get; private set; }
	public bool isComputed { get; private set; }

	public OurFile(FileInfo file, Dir parent, string uuid = null)
    {
		this.info = file;
		name = file.Name;
		this.parent = parent;
		path = parent.getLocalPath();
		if (uuid == null)
			uuid = Guid.NewGuid().ToString();
		this.uuid = uuid;
		//TODO use multi threading here
		//ThreadPool.QueueUserWorkItem(Hash);
		//Thread t = new Thread(Hash);
		//t.Start();
		//Hash(null);
	}

	public void ComputeHash()
    {
		ThreadPool.QueueUserWorkItem(Hash);
	}

	public string getRelativePath()
    {
		return $"{parent.getLocalPath()}\\{info.Name}";
    }

	private void Hash(Object thing)
    {
        using (FileStream fs = info.OpenRead())
        {
			using (BufferedStream b = new BufferedStream(fs))
			{
				var crc32 = Crc32Algorithm.Create();
				hash = BitConverter
						.ToString(
							crc32.ComputeHash(b)
							)
						.Replace("-", "")
						.ToLower();
			}
        }
		
		isComputed = true;
	}

	public void Encrypt()
	{
        //Error if file cannot be accessed
        try
        {
            using (FileStream fileRead = info.OpenRead())
			{
				using (FileStream fileWrite = File.OpenWrite(DirManager.getEncryptFile().FullName))
				{
					fileWrite.Seek(0, SeekOrigin.End);
					using (BufferedStream bRead = new BufferedStream(fileRead))
					{
						using (BufferedStream bWrite = new BufferedStream(fileWrite))
						{
							StreamWriter sr = new StreamWriter(bWrite);
							sr.Write($"[beginFile:{uuid}]");
							sr.Flush();
						
							using (CryptoStream cs = new CryptoStream(bWrite, DirManager.getKey().CreateEncryptor(), CryptoStreamMode.Write))
							{

								bWrite.Seek(0, SeekOrigin.End);
								bRead.CopyTo(cs);
							}
						}
					}
				}
			}
			DirManager.encryptCount++;
		}
        catch (Exception e)
        {
			DirManager.failed.Add(new FailedItem(this, e));
        }
		GC.Collect();
	}
	
}



public class Manifest
{
	public List<ManifestItem> Items = new List<ManifestItem>();
	public Manifest(List<ManifestItem> list = null)
    {
		if(list != null)
			Items = list;
    }
	public static Manifest Deserialize(string input)
    {
		List<ManifestItem> newItems = JsonConvert.DeserializeObject<List<ManifestItem>>(input);
		return new Manifest(newItems);
    }

	public ManifestItem getItem(string uuid)
    {
		foreach(var i in Items)
        {
			if(i.UUID == uuid)
            {
				return i;
            }
        }
		return null;
    }

	public void WriteToDisk(AesCryptoServiceProvider key)
	{
		if (DirManager.getEncryptFile().Exists)
		{
			using (FileStream fs = File.OpenWrite(DirManager.getEncryptFile().FullName))
			{
				fs.Seek(0, SeekOrigin.End);
				StreamWriter sw = new StreamWriter(fs);
				sw.Write($"[beginFile:manifest]");
				sw.Flush();
				fs.Seek(0, SeekOrigin.End);
				using (CryptoStream cs = new CryptoStream(fs, key.CreateEncryptor(), CryptoStreamMode.Write))
                {
					sw = new StreamWriter(cs);
					sw.Write(this.Serialize());

					//Cleanup
					sw.Flush();
					sw.Close();
					sw.Dispose();
				}
			}
        }
        else
        {
			Console.WriteLine("Encryption locker couldn't be found, failed to save manifest!");
			Console.WriteLine("If a file was generated, it's highly recommended you deleted it!");
			Console.ReadLine();
        }
	}

	public void Add(ManifestItem item)
    {
		Items.Add(item);
    }
	public void Remove(ManifestItem item)
    {
		Items.Remove(item);
    }

	/// <summary>
	/// Verifies a file exists in the manifest and is located in the same path.
	/// </summary>
	/// <param name="item"></param>
	/// <returns></returns>
	private bool Exists(ManifestItem item)
    {
		foreach(ManifestItem i in Items)
        {
			if (i.Name == item.Name &&
				i.Path == item.Path)
				return true;
        }
		return false;
    }
	private bool Exists(string name, string localPath)
	{
		foreach (ManifestItem i in Items)
		{
			if (i.Name == name &&
				i.Path == localPath)
				return true;
		}
		return false;
	}

	public string Serialize()
    {
		return JsonConvert.SerializeObject(Items);
	}

	/// <summary>
	/// Returns a JSON string
	/// </summary>
	/// <returns></returns>
    public override string ToString()
    {
		return Serialize();
    }

}

public class ManifestItem
{
	public ManifestItem(string path, string hash, string name, string uuid)
    {
		UUID = uuid; //Serves to obscure file and folder names
		Path = path;
		Hash = hash;
		Name = name;
    }
	public string UUID { get; set; }
	public string Path { get; set; }
	public string Hash { get; set; }
	public string Name { get; set; }
}

public class FailedItem
{
	public OurFile file { get; private set; }
	public Exception e { get; private set; }
	public FailedItem(OurFile file, Exception e)
    {
		this.file = file;
		this.e = e;
    }
}

public class LockerFile
{
	public int startIndex { get; private set; }
	public int endIndex { get; private set; }
	public string name { get; private set; }
	public LockerFile(int startIndex, int endIndex, string name)
    {
		this.startIndex = startIndex;
		this.endIndex = endIndex;
		this.name = name;
    }
}