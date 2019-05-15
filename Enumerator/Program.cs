using System;
using System.Net;
using System.Security.Principal;
using System.Management;
using System.IO;
using System.Net.NetworkInformation;
using System.DirectoryServices.AccountManagement;


namespace Enumerator
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=================================================================");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("                 Situational Awareness Tool                      ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("=================================================================");
            string user = Environment.UserName;
            Console.WriteLine("Current user context: " + user);
            string domain = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
            Console.WriteLine("Domain: " + domain);
            string computername = Dns.GetHostName();
            Console.WriteLine("Hostname: " + computername);
            
            WindowsIdentity ident = new WindowsIdentity(user);
            int initcount = 0;

            foreach (IdentityReference group in ident.Groups)
            {
                string c = Convert.ToString(group);
                if (c == "S-1-5-32-544")
                {
                    initcount++;

                }
            }


            if (initcount > 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[!] User {0} in local admin group", user);
                Console.ForegroundColor = ConsoleColor.White;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] User {0} NOT in local admin group", user);
                Console.ForegroundColor = ConsoleColor.White;

            }

            Console.WriteLine("");

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] Local Admin Members:");
            Console.ForegroundColor = ConsoleColor.White;

            PrincipalContext local = new PrincipalContext(ContextType.Machine);
            
            var lclgroup = GroupPrincipal.FindByIdentity(local, "Administrators");
            PrincipalSearcher searchlcl = new PrincipalSearcher();
            

            PrincipalSearchResult<Principal> rslts = lclgroup.GetMembers();

            foreach (Principal k in rslts)
            {
                Console.WriteLine(k.SamAccountName);
            }

            Console.WriteLine("");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] List of user accounts on {0}:", computername);
            Console.ForegroundColor = ConsoleColor.White;

            PrincipalContext mycontext = new PrincipalContext(ContextType.Machine, Environment.MachineName);
            UserPrincipal userp = new UserPrincipal(mycontext);
           
            PrincipalSearcher searchp = new PrincipalSearcher();
            searchp.QueryFilter = userp;
            PrincipalSearchResult<Principal> presult = searchp.FindAll();
            foreach (Principal m in presult)
            {
                try
                {
                    Console.WriteLine(m.SamAccountName);
                }
                catch
                {

                }


            }

            Console.WriteLine("");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] Internal Addresses found:");
            Console.ForegroundColor = ConsoleColor.White;
            NetworkInterface[] netinf = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface netinf2 in netinf)
            {
                Console.WriteLine("{0}: {1}", netinf2.Name, netinf2.GetIPProperties().UnicastAddresses[1].Address);
            }
            
            Console.WriteLine("");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] Antivirus Name and ProductState Search Results:");
            Console.ForegroundColor = ConsoleColor.White;

            ManagementObjectSearcher wmiinfo = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
            ManagementObjectCollection wmiinfo2 = wmiinfo.Get();

            foreach (ManagementObject antivirus in wmiinfo2)
            {
                Console.WriteLine("{0}: {1}",antivirus["displayName"],antivirus["productstate"]);
            }

            Console.WriteLine("");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] Endpoint Detection and Response Search Results:");
            Console.ForegroundColor = ConsoleColor.White;
            
            bool arch = Environment.Is64BitOperatingSystem;

            if (arch == true)
            {
                DirectoryInfo driversdir = new DirectoryInfo(@"c:\windows\sysnative\drivers");

                FileInfo[] lista = driversdir.GetFiles("*.sys");

                foreach (FileInfo file in lista)
                {
                    if (file.Name == "FeKern.sys" || file.Name == "WFP_MRT.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("FireEye found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "eaw.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Raytheon Cyber Solutions found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "rvsavd.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("CJSC Returnil Software found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "dgdmk.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Verdasys Inc. found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "mbamwatchdog.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Malwarebytes found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "edevmon.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("ESET found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "SentinelMonitor.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("SentinelOne found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "edrsensor.sys" || file.Name == "hbflt.sys" || file.Name == "bdsvm.sys" || file.Name == "gzflt.sys" || file.Name == "bddevflt.sys" || file.Name == "AVCKF.sys" || file.Name == "Atc.sys" || file.Name == "AVC3.SYS" || file.Name == "TRUFOS.SYS" || file.Name == "BDSandBox.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("BitDefender found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "HexisFSMonitor.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Hexis Cyber Solutions found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "CyOptics.sys" || file.Name == "CyProtectDrv32.sys" || file.Name == "CyProtectDrv64.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Cylance found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "aswSP.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Avast found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "mfeaskm.sys" || file.Name == "mfencfilter.sys" || file.Name == "epdrv.sys" || file.Name == "mfencoas.sys" || file.Name == "mfehidk.sys" || file.Name == "swin.sys" || file.Name == "hdlpflt.sys" || file.Name == "mfprom.sys" || file.Name == "MfeEEFF.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("McAfee found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "groundling32.sys" || file.Name == "groundling64.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Dell Secureworks found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "avgtpx86.sys" || file.Name == "avgtpx64.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("AVG Technologies found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "pgpwdefs.sys" || file.Name == "GEProtection.sys" || file.Name == "diflt.sys" || file.Name == "sysMon.sys" || file.Name == "ssrfsf.sys" || file.Name == "emxdrv2.sys" || file.Name == "reghook.sys" || file.Name == "spbbcdrv.sys" || file.Name == "bhdrvx86.sys" || file.Name == "bhdrvx64.sys" || file.Name == "SISIPSFileFilter.sys" || file.Name == "symevent.sys" || file.Name == "vxfsrep.sys" || file.Name == "vxfsrep.sys" || file.Name == "VirtFile.sys" || file.Name == "SymAFR.sys" || file.Name == "symefasi.sys" || file.Name == "symefa.sys" || file.Name == "symefa64.sys" || file.Name == "SymHsm.sys" || file.Name == "evmf.sys" || file.Name == "GEFCMP.sys" || file.Name == "VFSEnc.sys" || file.Name == "pgpfs.sys" || file.Name == "fencry.sys" || file.Name == "symrg.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Symantec found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "SAFE-Agent.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("SAFE-Cyberdefense found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "CybKernelTracker.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("CyberArk Software found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "klifks.sys" || file.Name == "klifaa.sys" || file.Name == "Klifsm.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Kaspersky found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "SAVOnAccess.sys" || file.Name == "savonaccess.sys" || file.Name == "sld.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Sophos found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "ssfmonm.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Webroot Software found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "CarbonBlackK.sys" || file.Name == "carbonblackk.sys" || file.Name == "cbk7.sys" || file.Name == "cbstream.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Carbon Black found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "Parity.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Bit9 Whitelisting Software found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "CRExecPrev.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Cybereason found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "im.sys" || file.Name == "csagent.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Crowdstrike found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "cfrmd.sys" || file.Name == "cmdccav.sys" || file.Name == "cmdguard.sys" || file.Name == "CmdMnEfs.sys" || file.Name == "MyDLPMF.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Comodo Security Solutions found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "PSINPROC.SYS" || file.Name == "PSINFILE.SYS" || file.Name == "amfsm.sys" || file.Name == "amm8660.sys" || file.Name == "amm6460.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Panda Security found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "fsgk.sys" || file.Name == "fsatp.sys" || file.Name == "fshs.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("F-Secure found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "esensor.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Engame found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "csacentr.sys" || file.Name == "csaenh.sys" || file.Name == "csareg.sys" || file.Name == "csascr.sys" || file.Name == "csaav.sys" || file.Name == "csaam.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Cisco found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "TMUMS.sys" || file.Name == "hfileflt.sys" || file.Name == "TMUMH.sys" || file.Name == "AcDriver.sys" || file.Name == "SakFile.sys" || file.Name == "SakFile.sys" || file.Name == "SakMFile.sys" || file.Name == "fileflt.sys" || file.Name == "TmEsFlt.sys" || file.Name == "tmevtmgr.sys" || file.Name == "TmFileEncDmk.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Trend Micro Inc found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "epregflt.sys" || file.Name == "medlpflt.sys" || file.Name == "dsfa.sys" || file.Name == "cposfw.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Check Point Software found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "psepfilter.sys" || file.Name == "cve.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Absolute found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "brfilter.sys" || file.Name == "BrCow_x_x_x_x.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Bromium found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "LRAgentMF.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("LogRhythm found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "libwamf.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("OPSWAT Inc found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }
                }

            }
            else
            {
                DirectoryInfo driversdir = new DirectoryInfo(@"c:\windows\system32\drivers");

                FileInfo[] listb = driversdir.GetFiles("*.sys");

                foreach (FileInfo file in listb)
                {
                    if (file.Name == "FeKern.sys" || file.Name == "WFP_MRT.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("FireEye found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "eaw.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Raytheon Cyber Solutions found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "rvsavd.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("CJSC Returnil Software found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "dgdmk.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Verdasys Inc. found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "mbamwatchdog.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Malwarebytes found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "edevmon.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("ESET found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "SentinelMonitor.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("SentinelOne found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "edrsensor.sys" || file.Name == "hbflt.sys" || file.Name == "bdsvm.sys" || file.Name == "gzflt.sys" || file.Name == "bddevflt.sys" || file.Name == "AVCKF.sys" || file.Name == "Atc.sys" || file.Name == "AVC3.SYS" || file.Name == "TRUFOS.SYS" || file.Name == "BDSandBox.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("BitDefender found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "HexisFSMonitor.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Hexis Cyber Solutions found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "CyOptics.sys" || file.Name == "CyProtectDrv32.sys" || file.Name == "CyProtectDrv64.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Cylance found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "aswSP.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Avast found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "mfeaskm.sys" || file.Name == "mfencfilter.sys" || file.Name == "epdrv.sys" || file.Name == "mfencoas.sys" || file.Name == "mfehidk.sys" || file.Name == "swin.sys" || file.Name == "hdlpflt.sys" || file.Name == "mfprom.sys" || file.Name == "MfeEEFF.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("McAfee found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "groundling32.sys" || file.Name == "groundling64.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Dell Secureworks found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "avgtpx86.sys" || file.Name == "avgtpx64.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("AVG Technologies found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "pgpwdefs.sys" || file.Name == "GEProtection.sys" || file.Name == "diflt.sys" || file.Name == "sysMon.sys" || file.Name == "ssrfsf.sys" || file.Name == "emxdrv2.sys" || file.Name == "reghook.sys" || file.Name == "spbbcdrv.sys" || file.Name == "bhdrvx86.sys" || file.Name == "bhdrvx64.sys" || file.Name == "SISIPSFileFilter.sys" || file.Name == "symevent.sys" || file.Name == "vxfsrep.sys" || file.Name == "vxfsrep.sys" || file.Name == "VirtFile.sys" || file.Name == "SymAFR.sys" || file.Name == "symefasi.sys" || file.Name == "symefa.sys" || file.Name == "symefa64.sys" || file.Name == "SymHsm.sys" || file.Name == "evmf.sys" || file.Name == "GEFCMP.sys" || file.Name == "VFSEnc.sys" || file.Name == "pgpfs.sys" || file.Name == "fencry.sys" || file.Name == "symrg.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Symantec found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "SAFE-Agent.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("SAFE-Cyberdefense found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "CybKernelTracker.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("CyberArk Software found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "klifks.sys" || file.Name == "klifaa.sys" || file.Name == "Klifsm.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Kaspersky found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "SAVOnAccess.sys" || file.Name == "savonaccess.sys" || file.Name == "sld.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Sophos found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "ssfmonm.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Webroot Software found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "CarbonBlackK.sys" || file.Name == "carbonblackk.sys" || file.Name == "cbk7.sys" || file.Name == "cbstream.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Carbon Black found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "Parity.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Bit9 Whitelisting Software found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "CRExecPrev.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Cybereason found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "im.sys" || file.Name == "csagent.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Crowdstrike found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "cfrmd.sys" || file.Name == "cmdccav.sys" || file.Name == "cmdguard.sys" || file.Name == "CmdMnEfs.sys" || file.Name == "MyDLPMF.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Comodo Security Solutions found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "PSINPROC.SYS" || file.Name == "PSINFILE.SYS" || file.Name == "amfsm.sys" || file.Name == "amm8660.sys" || file.Name == "amm6460.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Panda Security found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "fsgk.sys" || file.Name == "fsatp.sys" || file.Name == "fshs.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("F-Secure found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "esensor.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Engame found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "csacentr.sys" || file.Name == "csaenh.sys" || file.Name == "csareg.sys" || file.Name == "csascr.sys" || file.Name == "csaav.sys" || file.Name == "csaam.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Cisco found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "TMUMS.sys" || file.Name == "hfileflt.sys" || file.Name == "TMUMH.sys" || file.Name == "AcDriver.sys" || file.Name == "SakFile.sys" || file.Name == "SakFile.sys" || file.Name == "SakMFile.sys" || file.Name == "fileflt.sys" || file.Name == "TmEsFlt.sys" || file.Name == "tmevtmgr.sys" || file.Name == "TmFileEncDmk.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Trend Micro Inc found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "epregflt.sys" || file.Name == "medlpflt.sys" || file.Name == "dsfa.sys" || file.Name == "cposfw.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Check Point Software found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "psepfilter.sys" || file.Name == "cve.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Absolute found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "brfilter.sys" || file.Name == "BrCow_x_x_x_x.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Bromium found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "LRAgentMF.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("LogRhythm found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }

                    if (file.Name == "libwamf.sys")
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("OPSWAT Inc found!");
                        Console.ForegroundColor = ConsoleColor.White;
                    }
                }



            }

            Console.WriteLine("");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] AD Group Info for user {0}:", user);
            Console.ForegroundColor = ConsoleColor.White;
            
            PrincipalContext context = new PrincipalContext(ContextType.Domain);
            UserPrincipal usr = UserPrincipal.FindByIdentity(context, user);
            PrincipalSearchResult<Principal> groups = usr.GetAuthorizationGroups();

            foreach (GroupPrincipal g in groups)
            {
                Console.WriteLine(g.Name);

            }

            Console.WriteLine("");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] Domain Admins:");
            Console.ForegroundColor = ConsoleColor.White;
            PrincipalContext context2 = new PrincipalContext(ContextType.Domain);
            GroupPrincipal domadmins = GroupPrincipal.FindByIdentity(context2, "domain admins");
            
            foreach (Principal h in domadmins.GetMembers())
            {
                Console.WriteLine(h.SamAccountName);
            }

            Console.WriteLine("");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] Domain Controllers for {0}:", domain);
            Console.ForegroundColor = ConsoleColor.White;

            System.DirectoryServices.ActiveDirectory.Domain dom = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain();

            foreach (System.DirectoryServices.ActiveDirectory.DomainController dc in dom.DomainControllers)
            {
                Console.WriteLine("DC Name: " + dc.Name);
                Console.WriteLine("    [+] IP Address: " + dc.IPAddress);
            }

            Console.WriteLine("=================================================================");
            Console.WriteLine("DONE!");
            Console.WriteLine("=================================================================");
           
        }

    }
}
