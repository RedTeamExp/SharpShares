using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.DirectoryServices;
using System.Security.Principal;
using System.DirectoryServices.ActiveDirectory;
using System.Runtime.InteropServices;
using System.Threading;
using System.Security.AccessControl;
using System.IO;

namespace SharpShares
{
    class Program
    {
        public static Semaphore MaxThreads { get; set; }

        [DllImport("Netapi32.dll", SetLastError = true)]
        public static extern int NetWkstaGetInfo(string servername, int level, out IntPtr bufptr);

        [DllImport("Netapi32.dll", SetLastError = true)]
        static extern int NetApiBufferFree(IntPtr Buffer);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetShareEnum(
            StringBuilder ServerName,
            int level,
            ref IntPtr bufPtr,
            uint prefmaxlen,
            ref int entriesread,
            ref int totalentries,
            ref int resume_handle
        );

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WKSTA_INFO_100
        {
            public int platform_id;
            public string computer_name;
            public string lan_group;
            public int ver_major;
            public int ver_minor;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHARE_INFO_0
        {
            public string shi0_netname;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHARE_INFO_1
        {
            public string shi1_netname;
            public uint shi1_type;
            public string shi1_remark;
            public SHARE_INFO_1(string sharename, uint sharetype, string remark)
            {
                this.shi1_netname = sharename;
                this.shi1_type = sharetype;
                this.shi1_remark = remark;
            }
            public override string ToString()
            {
                return shi1_netname;
            }
        }

        const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;
        const int NERR_Success = 0;

        private enum NetError : uint
        {
            NERR_Success = 0,
            NERR_BASE = 2100,
            NERR_UnknownDevDir = (NERR_BASE + 16),
            NERR_DuplicateShare = (NERR_BASE + 18),
            NERR_BufTooSmall = (NERR_BASE + 23),
        }

        private enum SHARE_TYPE : uint
        {
            STYPE_DISKTREE = 0,
            STYPE_PRINTQ = 1,
            STYPE_DEVICE = 2,
            STYPE_IPC = 3,
            STYPE_SPECIAL = 0x80000000,
        }

        public static SHARE_INFO_1[] EnumNetShares(string Server)
        {
            List<SHARE_INFO_1> ShareInfos = new List<SHARE_INFO_1>();
            int entriesread = 0;
            int totalentries = 0;
            int resume_handle = 0;
            int nStructSize = Marshal.SizeOf(typeof(SHARE_INFO_1));
            IntPtr bufPtr = IntPtr.Zero;
            StringBuilder server = new StringBuilder(Server);
            int ret = NetShareEnum(server, 1, ref bufPtr, MAX_PREFERRED_LENGTH, ref entriesread, ref totalentries, ref resume_handle);
            if (ret == NERR_Success)
            {
                IntPtr currentPtr = bufPtr;
                for (int i = 0; i < entriesread; i++)
                {
                    SHARE_INFO_1 shi1 = (SHARE_INFO_1)Marshal.PtrToStructure(currentPtr, typeof(SHARE_INFO_1));
                    ShareInfos.Add(shi1);
                    currentPtr += nStructSize;
                }
                NetApiBufferFree(bufPtr);
                return ShareInfos.ToArray();
            }
            else
            {
                ShareInfos.Add(new SHARE_INFO_1("ERROR=" + ret.ToString(), 10, string.Empty));
                return ShareInfos.ToArray();
            }
        }


        
        public static List<DomainController> GetDomainControllers()
        {
            List<DomainController> domainControllers = new List<DomainController>();
            try
            {
                Domain domain = Domain.GetCurrentDomain();
                foreach (DomainController dc in domain.DomainControllers)
                {
                    domainControllers.Add(dc);
                }
            }
            catch { }
            return domainControllers;
        }


        //输出hostname:ip
        public static void GetComputerAddresses(List<string> computers)
        {
            foreach (string computer in computers)
            {
                try
                {
                    IPAddress[] ips = System.Net.Dns.GetHostAddresses(computer);
                    foreach (IPAddress ip in ips)
                    {
                        if (!ip.ToString().Contains(":"))
                        {
                            Console.WriteLine("{0}: {1}", computer, ip);
                        }
                    }
                }
                catch(Exception ex)
                {
                    //Console.WriteLine("[X] ERROR: {0}", ex.Message);
                }
            }
        }


        //利用ldap获取域成员机器的机器名
        public static List<string> GetComputers()
        {
            List<string> computerNames = new List<string>();
            List<DomainController> dcs = GetDomainControllers();
            if (dcs.Count > 0)
            {
                try
                {
                    Domain domain = Domain.GetCurrentDomain();
                    //domain.
                    string currentUser = WindowsIdentity.GetCurrent().Name.Split('\\')[1];//当前用户名


   
                    using (DirectoryEntry entry = new DirectoryEntry(String.Format("LDAP://{0}", dcs[0])))
                    {
                        using (DirectorySearcher mySearcher = new DirectorySearcher(entry))
                        {
                            mySearcher.Filter = ("(objectClass=computer)");

                            // 读所有的对象
                            mySearcher.SizeLimit = 0;

                            // 读取250个对象的页面中的数据,确保此值低于您在AD域中配置的限制（如果有限制）
                            mySearcher.PageSize = 250;

                            //让搜索者知道将要使用哪些属性，并仅加载那些属性
                            mySearcher.PropertiesToLoad.Add("name");

                            foreach (SearchResult resEnt in mySearcher.FindAll())
                            {
                                //  注意：属性可以包含多个值
                                if (resEnt.Properties["name"].Count > 0)
                                {
                                    string computerName = (string)resEnt.Properties["name"][0];
                                    Console.WriteLine(computerName);
                                    computerNames.Add(computerName);
                                }
                            }
                        }
                    }
                }
                catch { }
            }
            else
            {
                Console.WriteLine("[x]:无法获取域控制器列表.");
            }
            return computerNames;
        }

        public static void GetComputerShares(string computer, bool publicOnly = false)
        {
            string[] errors = { "ERROR=53", "ERROR=5" };
            SHARE_INFO_1[] computerShares = EnumNetShares(computer);
            if (computerShares.Length > 0)
            {

                //这一段，标准写法
                List<string> readableShares = new List<string>();
                List<string> unauthorizedShares = new List<string>();
                List<string> writeableShares = new List<string>();
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                string userSID = identity.User.Value;
                foreach (SHARE_INFO_1 share in computerShares)
                {
                    try
                    {
                        string path = String.Format("\\\\{0}\\{1}", computer, share.shi1_netname);
                        var files = System.IO.Directory.GetFiles(path);
                        readableShares.Add(share.shi1_netname);//可读
                        AuthorizationRuleCollection rules = Directory.GetAccessControl(path).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));

                       //列出可写
                        foreach (FileSystemAccessRule rule in rules)
                        {
                            //https://stackoverflow.com/questions/130617/how-do-you-check-for-permissions-to-write-to-a-directory-or-file
                            // compare SID of group referenced in ACL to groups the current user is a member of
                            if (rule.IdentityReference.ToString() == userSID || identity.Groups.Contains(rule.IdentityReference))
                            {
                                // plenty of other FileSystem Rights to look for
                                // https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights
                                if ((//rule.FileSystemRights.HasFlag(FileSystemRights.CreateFiles) ||
                                     //rule.FileSystemRights.HasFlag(FileSystemRights.WriteAttributes) ||
                                     //rule.FileSystemRights.HasFlag(FileSystemRights.WriteData) ||
                                     //rule.FileSystemRights.HasFlag(FileSystemRights.WriteExtendedAttributes) ||
                                     //rule.FileSystemRights.HasFlag(FileSystemRights.CreateDirectories) ||
                                    rule.FileSystemRights.HasFlag(FileSystemRights.Write)) && rule.AccessControlType == AccessControlType.Allow)
                                {
                                    writeableShares.Add(share.shi1_netname);
                                    break;
                                }
                            }
                        }

                    }
                    //可写参考https://github.com/mitchmoser/SharpShares/blob/master/SharpShares/Program.cs



                    catch
                    {
                        if (!errors.Contains(share.shi1_netname))
                        {
                            unauthorizedShares.Add(share.shi1_netname);
                        }
                    }
                }




                if (unauthorizedShares.Count > 0 || readableShares.Count > 0)
                {
                    if (publicOnly)
                    {
                        if (readableShares.Count > 0)
                        {
                            string output = string.Format("[+]{0}机器开启的共享如下:\n", computer);
                            //output += "[--- Listable Shares ---]\n";
                            //Console.WriteLine("Shares for {0}:", computer);
                            //Console.WriteLine("\t[--- Listable Shares ---]");
                            foreach (string share in readableShares)
                            {
                                output += string.Format("\t\t{0}\n", share);
                            }
                            Console.WriteLine(output);
                        }
                    }
                    else
                    {
                        string output = string.Format("[+]{0}机器开启的共享如下:\n", computer);
                        if (unauthorizedShares.Count > 0)
                        {
                            output += "[+]不可读共享\n";
                            foreach (string share in unauthorizedShares)
                            {
                                output += string.Format("\t[>]{0}\n", share);
                            }
                        }
                        if (readableShares.Count > 0)
                        {
                            output += "[+]可读共享\n";
                            foreach (string share in readableShares)
                            {
                                output += string.Format("\t[>]{0}\n", share);
                                //string pathshare = string.Format("\\\\{0}\\{1}", computer, share);//列出文件
                                //ListFiles(new DirectoryInfo(pathshare));
                            }
                        }
                        if (writeableShares.Count > 0)
                        {
                            output += "[+]可写共享\n";
                            foreach (string share in writeableShares)
                            {
                                output += String.Format("\t[>]{0}\n", share);

                            }
                        }
                        Console.WriteLine(output);
                    }
                }
            }
        }

        public static void GetAllShares(List<string> computers, bool publicOnly = false)
        {
            List<Thread> runningThreads = new List<Thread>();
            foreach(string computer in computers)
            {
                Thread t = new Thread(() => GetComputerShares(computer, publicOnly));
                t.Start();
                runningThreads.Add(t);
            }
            foreach(Thread t in runningThreads)
            {
                t.Join();
            }
        }

        static void GetComputerVersions(List<string> computers)
        {
            foreach(string computer in computers)
            {
                Console.WriteLine("Comptuer: {0}", computer);
                string serverName = String.Format("\\\\{0}", computer);
                Console.WriteLine(serverName);
                IntPtr buffer;
                var ret = NetWkstaGetInfo(serverName, 100, out buffer);
                var strut_size = Marshal.SizeOf(typeof(WKSTA_INFO_100));
                Console.WriteLine("Ret is:");
                Console.WriteLine(ret);
                if (ret == NERR_Success)
                {
                    var info = (WKSTA_INFO_100)Marshal.PtrToStructure(buffer, typeof(WKSTA_INFO_100));
                    if (!string.IsNullOrEmpty(info.computer_name))
                    {
                        Console.WriteLine(info.computer_name);
                        Console.WriteLine(info.platform_id);
                        Console.WriteLine(info.ver_major);
                        Console.WriteLine(info.ver_minor);
                        Console.WriteLine(info.lan_group);
                    }
                }
            }
        }


        public static void ListFiles(FileSystemInfo info)
        {
            if (!info.Exists) return;
            DirectoryInfo dir = info as DirectoryInfo;
            //不是目录
            if (dir == null) return;
            try
            {
                FileSystemInfo[] files = dir.GetFileSystemInfos();
                for (int i = 0; i < files.Length; i++)
                {
                    FileInfo file = files[i] as FileInfo;
                    //是文件
                    if (file != null)
                        Console.WriteLine(file.FullName);
                    //对于子目录，进行递归调用
                    else
                        ListFiles(files[i]);
                }
            }
            catch { }
        }

        static void Main(string[] args)
        {


            //String servername = args[0];
            //Console.WriteLine(servername);
            //GetComputerShares(servername);



            var computers = GetComputers();
            //获取不到域机器列表
            //if (computers.Count == 0)
            //{
            //    computers.Add("127.0.0.1");
            //}



            Console.WriteLine("[*]:解析的{0}个计算机对象.", computers.Count);
            ThreadPool.SetMaxThreads(10, 10);
            if (args.Contains("ips"))
            {
                GetComputerAddresses(computers);
            }
            else if (args.Contains("shares"))
            {
                bool pubOnly = false;
                if (args.Contains("--public-only"))
                {
                    pubOnly = true;
                }
                if (args.Length < 2 || (args.Length == 2 && pubOnly))
                {

                    GetAllShares(computers, pubOnly);
                }
                else if (args[1] == "--public-only")
                {
                    GetAllShares(computers, true);
                }
                else
                {
                    Console.WriteLine("Attempting to enumerate shares for: {0}", args[1]);
                    List<string> comps = new List<string>();
                    comps.Add(args[1]);
                    GetAllShares(comps, pubOnly);
                }
            }
            else if (args.Contains("versions"))
            {
                GetComputerVersions(computers);
            }
            else
            {
                Console.WriteLine("[x]: 参数错误. 请输入 \"ips\" or \"shares\".");
            }
        }
    }
}


//错误号 5，拒绝访问【很可能你使用的用户不是管理员权限的，先提升权限】
//错误号 51，Windows 无法找到网络路径【网络有问题】
//错误号 53，找不到网络路径【ip 地址错误；目标未开机；目标 lanmanserver 服务未启动；目标有防火墙（端口过滤）】
//错误号 67，找不到网络名【你的 lanmanworkstation 服务未启动；目标删除了 ipc$；】
//错误号 1219，提供的凭据与已存在的凭据集冲突【你已经和对方建立了一个ipc$，请删除后再连】
//错误号 1326，未知的用户名或错误密码【原因很明显了】
//错误号 1385，登录失败：未授予用户在此计算机上的请求登录类型
//---
//情况1：可能是你在“拒绝从网络访问这台计算机”功能中拒绝了该用户的访问，解决方法如下：
//开始-->运行-->gpedit.msc计算机配置-->Windows设置-->安全设置-->本地策略-->用户权利指派-->拒绝从网络访问这台计算机-->删除你要正常连接的用户
//情况2：
//(1)网络访问为：经典
//(2)来宾账户状态：已启用，
//(3)拒绝从网络访问这台计算机里有Guest用户或组
//(4)你执行net use \\xxx.xxx.xxx.xxx\IPC$ "123456" /user:"xxx" 输入的用户名是随便输入的，这时也会遇到这个错误信息，因为当你连接的用户不存在时，net use会默认用Guest用户来进行连接，而Guest用户已拒绝从网络访问，所以也会出现这种错误
//---
//错误号 1792，试图登录，但是网络登录服务没有启动【目标NetLogon服务未启动[连接域控会出现此情况]】
//错误号 2242，此用户的密码已经过期【目标有帐号策略，强制定期要求更改密码】
