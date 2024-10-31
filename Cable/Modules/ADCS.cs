using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.DirectoryServices;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cable.Modules
{
    public class ADCS
    {
        public static void caLookup()
        {
            DirectoryEntry de = new DirectoryEntry("LDAP://RootDSE");
            String context = de.Properties["configurationNamingContext"].Value.ToString();

            string root = "CN=Enrollment Services,CN=Public Key Services,CN=Services," + context;

            DirectoryEntry newDe = new DirectoryEntry("LDAP://" + root);
            DirectorySearcher ds = new DirectorySearcher(newDe);

            ds.Filter = "(objectCategory=pKIEnrollmentService)";

            SearchResultCollection results = ds.FindAll();

            if (results.Count == 0)
            {
                Console.WriteLine("[!] No CA's found");
            }

            foreach (SearchResult sr in results)
            {
                if (sr.Properties.Contains("name"))
                {
                    Console.WriteLine("[+] Found CA: " + sr.Properties["name"][0].ToString());   
                }
                if (sr.Properties.Contains("dnshostname"))
                {
                    Console.WriteLine("\t|__ Hostname: " + sr.Properties["dnshostname"][0].ToString());
                    
                }
            }

            }
        public static void templateLookup()
        {

            DirectoryEntry de = new DirectoryEntry("LDAP://RootDSE");
            String context = de.Properties["configurationNamingContext"].Value.ToString();

            DirectoryEntry newDe = new DirectoryEntry("LDAP://" + context);
            DirectorySearcher ds = new DirectorySearcher(newDe);

            ds.Filter = "(objectCategory=pKICertificateTemplate)";
            SearchResultCollection results = ds.FindAll();

            if (results.Count == 0)
            {
                Console.WriteLine("[!] No certificate templates found");
            }

            foreach (SearchResult sr in results)
            {
                if (sr.Properties.Contains("name"))
                {
                    Console.WriteLine("[+] Found Template: " + sr.Properties["name"][0].ToString());
                }
                if (sr.Properties.Contains("mspki-enrollment-flag"))
                {
                    Console.WriteLine("\t|__ mspki-enrollment-flag: " + (hCable.msPKIEnrollmentFlag)Convert.ToInt32(sr.Properties["mspki-enrollment-flag"][0].ToString()));
                }

                if (sr.Properties.Contains("mspki-certificate-name-flag"))
                {
                    Console.WriteLine("\t|__ mspki-certificate-name-flag: " + (hCable.msPKICertificateNameFlag)Convert.ToInt32(sr.Properties["mspki-certificate-name-flag"][0].ToString()));
                }

                if (sr.Properties.Contains("pKIExtendedKeyUsage"))
                {
                    var EKUs = sr.Properties["pKIExtendedKeyUsage"];
                    if (EKUs.Count > 0)
                    {
                        Console.WriteLine("\t|__ pKIExtendedKeyUsage:");
                        for (int e = 0; e < EKUs.Count; e++)
                        {
                            Console.WriteLine("\t|    |__ " + (new Oid(sr.Properties["pKIExtendedKeyUsage"][e].ToString()).FriendlyName));
                        }
                    }
                }
                Console.Write("\n");
            }
        }
    }
}
