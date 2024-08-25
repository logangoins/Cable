using System;
using System.Linq;
using System.DirectoryServices.ActiveDirectory;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;
using System.Windows.Markup;

namespace SillyEnum
{
    internal class Program
    {
        static void Help()
        {
            Console.WriteLine("Enumerate Active Directory in a very silly way\nUsage:\n\tSillyEnum [Options]\nOptions:\n\tdclist - List Domain Controllers and their info\n\tusers - List Domain Users and their info\n\tcomputers - List Domain Computers and their info\n");
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
            SearchResultCollection results;
            DirectorySearcher ds = null;

            DirectoryEntry de = new DirectoryEntry();
            ds = new DirectorySearcher(de);
            ds.Filter = "(&(ObjectCategory=person)(ObjectClass=user))";

            results = ds.FindAll();

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

        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                if (args.Contains("--help") || args.Contains("-h"))
                {
                    Help();
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
            }
            else
            {
                Help();
            }
        }
    }
}
