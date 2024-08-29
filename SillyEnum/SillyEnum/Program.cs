using System;
using System.Linq;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices;
using System.Security.Principal;
using System.Net;

namespace SillyEnum
{
    internal class Program
    {
        static void Help()
        {
            string helptext =
                "\nEnumerate LDAP in a very silly way\n" +
                "\nUsage:\n" +
                "\tSillyEnum.exe [Options]\n" +
                "Options:\n" +
                "\tusers: Enumerate user objects\n" +
                "\tcomputers: Enumerate computer objects\n" +
                "\tspns: Enumerate objects with servicePrincipalName set\n" +
                "\tdclist: Enumerate domain controller objects\n" +
                "\tadmins: Enumerate accounts with adminCount set to 1\n";


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

        static void Main(string[] args)
        {
            try
            {
                if (args.Length > 1)
                {
                    Console.WriteLine("Please only supply a single option");
                }
                else if (args.Contains("dclist"))
                {
                    Console.WriteLine("[+] Enumerating Domain Controllers:");
                    dclist();
                }
                else if (args.Contains("users"))
                {
                    Console.WriteLine("[+] Enumerating user accounts:");
                    users();
                }
                else if (args.Contains("computers"))
                {
                    Console.WriteLine("[+] Enumerating computer accounts:");
                    computers();
                }
                else if (args.Contains("spns"))
                {
                    Console.WriteLine("[+] Enumerating accounts with servicePrincipalName set: ");
                    spns();
                }
                else if (args.Contains("admins"))
                {
                    Console.WriteLine("[+] Enumerating accounts with adminCount set to 1:");
                    admins();
                }
                else
                {
                    Help();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Exception: " + ex.Message);
            }
        }
    }
}
