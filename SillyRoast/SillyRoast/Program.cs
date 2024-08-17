using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;

namespace SillyRoast
{
    internal class Program
    {

        static string GetCurrentDomainPath()
        {
            DirectoryEntry de = new DirectoryEntry("LDAP://RootDSE");

            // Console.WriteLine("LDAP://" + de.Properties["defaultNamingContext"][0].ToString());
            return "LDAP://" + de.Properties["defaultNamingContext"][0].ToString();
        }

        static SearchResultCollection Query(string query)
        {
            SearchResultCollection results;
            DirectorySearcher ds = null;

            DirectoryEntry de = new DirectoryEntry(GetCurrentDomainPath());
            de.AuthenticationType = AuthenticationTypes.Secure;
            ds = new DirectorySearcher(de);
            ds.Filter = query;

            results = ds.FindAll();
            Console.WriteLine(results.Count);
            foreach (SearchResult sr in results)
            {
                // Using the index zero (0) is required!
                Console.WriteLine(sr.Properties["name"][0].ToString());
            }

            return results;
        }

        static string Kerberoast(string[] args)
        {
            string spnFilter = "(&(&(servicePrincipalName=*)(!samAccountName=krbtgt))(!useraccountcontrol:1.2.840.113556.1.4.803:=2)(samAccountType=805306368))";
            SearchResultCollection result = Query(spnFilter);
            return null;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("\r\n\r\n.________.___ .___    .___     ____   ____.______  ._______  .______  ._____________._\r\n|    ___/: __||   |   |   |    \\   \\_/   /: __   \\ : .___  \\ :      \\ |    ___/\\__ _:|\r\n|___    \\| : ||   |   |   |     \\___ ___/ |  \\____|| :   |  ||   .   ||___    \\  |  :|\r\n|       /|   ||   |/\\ |   |/\\     |   |   |   :  \\ |     :  ||   :   ||       /  |   |\r\n|__:___/ |   ||   /  \\|   /  \\    |___|   |   |___\\ \\_. ___/ |___|   ||__:___/   |   |\r\n   :     |___||______/|______/            |___|       :/         |___|   :       |___|\r\n                                                      :");
            Console.WriteLine("Kerberoast and ASREProast very silly - v0.1\n");

            if (args.Length > 0)
            {
                switch (args[0])
                {
                    case "kerberoast":
                        Console.WriteLine("Kerberoasting...");
                        string krbREP = Kerberoast(args);
                        break;
                    case "asreproast":
                        Console.WriteLine("ASREProasting...");
                        break;
                }

            }
            else
            {
                Console.WriteLine("Please supply arguments: Type \"--help\" to see a list of commands\n");
            }



        }
    }
}
