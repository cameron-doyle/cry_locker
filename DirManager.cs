﻿using System;
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
	public static DirectoryInfo SaveLocation { private get; set; }
	public static AesCryptoServiceProvider key { private get; set; }
	private bool _isEncrypted = false;

	public DirManager(DirectoryInfo root, DirectoryInfo saveLocation = null, AesCryptoServiceProvider encryptionKey = null)
	{
		//DirManager.maxRam = maxRam * 1048576;
		SaveLocation = saveLocation;
		key = encryptionKey;
		Dir._nonComputed = new List<OurFile>();
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

	public static DirectoryInfo getSaveLocation()
	{
		if (SaveLocation == null)
			throw new NullReferenceException("SaveLocation was never set!");
		return SaveLocation;
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
	private DirectoryInfo self;
	private List<Dir> subDirs = new List<Dir>();
	private List<OurFile> files = new List<OurFile>();
	private bool filesLoaded = false;
	private bool subDirsLoaded = false;
	public double size { get; private set; }
	public static List<OurFile> _nonComputed;

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
			_nonComputed.Add(nf);
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
		if (_nonComputed.Count > 0)
		return false;
		else return true;
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
			return $"./{self.Name}/";
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
        GC.Collect();
		//hash = info.GetHashCode().ToString();
		Dir._nonComputed.Remove(this);
		isComputed = true;
	}

	public void Encrypt()
	{
		AesCryptoServiceProvider key = DirManager.getKey();
		DirectoryInfo location = DirManager.getSaveLocation();


        //Error if file cannot be accessed
        try
        {
			//Buffered
			using (FileStream fileRead = info.OpenRead())
            {
                using (FileStream fileWrite = File.OpenWrite($"{location.FullName}\\{info.Name}"))
                {
					using (BufferedStream bRead = new BufferedStream(fileRead))
					{
						using (BufferedStream bWrite = new BufferedStream(fileWrite))
						{
							using (CryptoStream cs = new CryptoStream(bWrite, key.CreateEncryptor(), CryptoStreamMode.Write))
							{
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

	public void WriteToDisk(DirectoryInfo location, AesCryptoServiceProvider key)
	{
        using (FileStream fs = File.Create($"{location.FullName}\\manifest"))
        {
            using (CryptoStream cs = new CryptoStream(fs, key.CreateEncryptor(), CryptoStreamMode.Write))
            {
                using (StreamWriter sw = new StreamWriter(cs))
                {
                    sw.Write(this.Serialize());
                }
            }
        }
        
		/*using (FileStream fs = File.Create($"{location.FullName}\\manifest"))
		{
			
			using (StreamWriter sw = new StreamWriter(fs))
			{
				sw.Write(this.Serialize());
			}
			
		}*/
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