using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cable.Modules
{
    public class ADCS
    {
        public static void templateLookup()
        {
            DirectoryEntry de = new DirectoryEntry("LDAP://RootDSE");
            String context = de.Properties["configurationNamingContext"].Value.ToString();

            string sbase = "CN=Certificate Templates,CN=Public Key Services,CN=Services," + context;

            DirectoryEntry newDe = new DirectoryEntry("LDAP://" + sbase);
            DirectorySearcher ds = new DirectorySearcher(newDe);

            ds.Filter = "(objectCategory=pKICertificateTemplate)";
            SearchResultCollection results = ds.FindAll();

            foreach (SearchResult sr in results)
            {
                if (sr.Properties.Contains("name"))
                {
                    Console.WriteLine("Template: " + sr.Properties["name"][0].ToString());
                    Console.WriteLine("=======================================");
                }
                if (sr.Properties.Contains("mspki-enrollment-flag"))
                {
                    Console.WriteLine((Cabnums.msPKIEnrollmentFlag)Convert.ToInt32(sr.Properties["mspki-enrollment-flag"][0].ToString()));
                }

                if (sr.Properties.Contains("mspki-certificate-name-flag"))
                {
                    Console.WriteLine((Cabnums.msPKICertificateNameFlag)Convert.ToInt32(sr.Properties["mspki-certificate-name-flag"][0].ToString()));
                }

                if (sr.Properties.Contains("pKIExtendedKeyUsage"))
                {
                    var EKUs = sr.Properties["pKIExtendedKeyUsage"];
                    if (EKUs.Count > 0)
                    {
                        for (int e = 0; e < EKUs.Count; e++)
                        {
                            Console.WriteLine(new Oid(sr.Properties["pKIExtendedKeyUsage"][e].ToString()).FriendlyName);
                        }
                    }
                }
                Console.Write("\n");
            }
        }
    }
}
