﻿using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;


namespace Cable.Modules
{

    public class ArgParse
    {

        public static void Help()
        {
            string help =
                "Cable.exe [Module]\n" +
                "Modules:\n" +
                "\tenum [Options]            - Enumerate LDAP\n" +
                "\tkerberoast <account>      - Kerberoast a potentially supplied account, or everything\n" +
                "\tdclist                    - List Domain Controllers in the current Domain\n" +
                "\trbcd [Options]            - Write or remove the msDs-AllowedToActOnBehalfOfOtherIdentity attribute\n" +
                "\ttrusts                    - Enumerate Active Directory Domain and Forest Trusts\n" +
                "\tca                        - Enumerate any active Active Directory Certifcate Services (ADCS) CA's\n" +
                "\ttemplates                 - Enumerate Active Directory Certificate Services (ADCS) Templates\n" +
                "\tuser [Options]            - Preform general operations on user accounts\n" +
                "\tgroup [Options]           - Enumerate group membership, add, and remove users from groups\n\n" +

                "Module Options\n" +
                "enum:\n" +
                "\t--users                   - Enumerate user objects\n" +
                "\t--computers               - Enumerate computer objects\n" +
                "\t--groups                  - Enumerate group objects\n" +
                "\t--gpos                    - Enumerate Group Policy objects\n" +
                "\t--spns                    - Enumerate objects with servicePrincipalName set\n" +
                "\t--asrep                   - Enumerate accounts that do not require Kerberos pre-authentication\n" +
                "\t--admins                  - Enumerate accounts with adminCount set to 1\n" +
                "\t--constrained             - Enumerate accounts with msDs-AllowedToDelegateTo set\n" +
                "\t--unconstrained           - Enumerate accounts with the TRUSTED_FOR_DELEGATION flag set\n" +
                "\t--rbcd                    - Enumerate accounts with msDs-AllowedToActOnBehalfOfOtherIdentity set\n" +
                "\t--query <query>           - Enumerate objects with a custom query\n" +
                "\t--filter <attr, attr>     - Enumerate objects for specific attributes\n\n" +

                "rbcd:\n" +
                "\t--write                   - Operation to write msDs-AllowedToActOnBehalfOfOtherIdentity\n" +
                "\t--delegate-to <account>   - Target account to delegate access to\n" +
                "\t--delegate-from <account> - Controlled account to delegate from\n" +
                "\t--flush <account>         - Operation to flush msDs-AllowedToActOnBehalfOfOtherIdentity on an account\n\n" +
                
                "user:\n" +
                "\t--setspn <value>          - Write to an objects servicePrincipalName attribute\n" +
                "\t--removespn <value>       - Remove a specified value off the servicePrincipalName attribute\n" +
                "\t--user <account>          - Specify user account to preform operations on\n" +
                "\t--password <password>     - Change an accounts password\n\n" +

                "group:\n" +
                "\t--getmembership           - Operation to get Active Directory group membership\n" +
                "\t--group <group>           - The group used for an operation specified\n" +
                "\t--add <account>           - Add a specified account to the group selected\n" +
                "\t--remove <account>        - Remove a specified account from the group selected\n";

            Console.WriteLine(help);

        }

        static List<string> sMods = new List<string> 
        { 
            "enum",
            "kerberoast",
            "dclist",
            "rbcd",
            "trusts",
            "templates",
            "ca",
            "group",
            "user"
        };

        public static Dictionary<string, string> Parse(string[] args, string[] flags, string[] options)
        {
            Dictionary<string, string> cmd = new Dictionary<string, string>();

            foreach (string flag in flags)
            {
                if (args.Contains(flag))
                {
                    try
                    {
                        cmd.Add(flag, args[Array.IndexOf(args, flag) + 1]);
                    }
                    catch
                    {
                        Console.WriteLine("[!] Please supply all the valid options, use \"Cable.exe -h\" for more information");
                        return null;
                    }
                }
            }

            foreach (string option in options)
            {
                if (args.Contains(option))
                {
                    cmd.Add(option, "True");
                }
                else
                {
                    cmd.Add(option, "False");
                }
            }

            return cmd;
        }

        public static void Execute(string[] args)
        {

            if(args.Contains("--help") || args.Contains("-h") || args.Length == 0)
            {
                Help();
            }
            else if (sMods.Contains(args.First()))
            {
                try
                {
                    switch (args.First().ToLower())
                    {
                        case "enum":
                            if (args.Length > 1)
                            {
                                string query = null;
                                string filter = null;
                                string type = null;
                                string selection = null;
                                List<string> attributes = new List<string>() { "samaccountname", "objectsid", "distinguishedname" };
                                string[] enumFlags = { "--query", "--filter" };
                                string[] enumOptions = { "--users", "--computers", "--groups", "--gpos", "--spns", "--asrep", "--admins", "--unconstrained", "--constrained", "--rbcd"};

                                Dictionary<string, string> enumcmd = Parse(args, enumFlags, enumOptions);
                                if(enumcmd == null)
                                {
                                    return;
                                }
                                enumcmd.TryGetValue("--query", out query);
                                enumcmd.TryGetValue("--filter", out filter);
                                if(filter != null)
                                {
                                    attributes = filter.Split(',').Select(a => a.Trim()).Select(a => a.ToLower()).ToList();
                                }
                                if (query != null)
                                {
                                    type = "query";
                                }
                                else
                                {
                                    foreach(string option in enumOptions)
                                    {
                                        enumcmd.TryGetValue(option, out selection);
                                        if(selection == "True")
                                        {
                                            type = option;
                                        }
                                    }
                                }

                                Enumerate.Enum(type, query, attributes);
                            }
                            else
                            {
                                Help();
                            }
                            break;
                        case "kerberoast":
                            if (args.Length > 1)
                            {
                                string[] kspn = { args[1] };
                                Kerberoast.Roast(kspn);
                            }
                            else
                            {
                                string[] spns = Kerberoast.GetSPNs();
                                if(spns == null)
                                {
                                    return;
                                }
                                Kerberoast.Roast(spns);
                            }
                            break;
                        case "dclist":
                            Enumerate.Dclist();
                            break;
                        case "rbcd":
                            string delegate_from = null;
                            string delegate_to = null;
                            string account = null;
                            string write = null;

                            string[] rbcdFlags = { "--delegate-from", "--delegate-to", "--flush" };
                            string[] rbcdOptions = { "--write" };

                            Dictionary<string, string> rbcdcmd = Parse(args, rbcdFlags, rbcdOptions);
                            if(rbcdcmd == null)
                            {
                                return;
                            }
                            rbcdcmd.TryGetValue("--delegate-from", out delegate_from);
                            rbcdcmd.TryGetValue("--delegate-to", out delegate_to);
                            rbcdcmd.TryGetValue("--flush", out account);
                            rbcdcmd.TryGetValue("--write", out write);

                            if (write == "True")
                            {
                                if (delegate_from == null || delegate_to == null)
                                {
                                    Console.WriteLine("[!] You must specify all the parameters required for an RBCD write ");
                                }
                                else
                                {
                                    RBCD.WriteRBCD(delegate_to, delegate_from);
                                }
                            }
                            else if (write == "False")
                            {
                                if (account == null)
                                {
                                    Console.WriteLine("[!] You must specify all the parameters required for an RBCD flush");

                                }
                                else
                                {
                                    RBCD.FlushRBCD(account);
                                }
                            }
                            else
                            {
                                Help();
                            }
                            break;
                        case "trusts":
                            Enumerate.enumTrusts();
                            break;
                        case "templates":
                            ADCS.templateLookup();
                            break;
                        case "ca":
                            ADCS.caLookup();
                            break;
                        case "user":
                            string user = null;
                            string aspn = null;
                            string rspn = null;
                            string password = null;

                            string[] userFlags = { "--setspn", "--removespn", "--user", "--password" };
                            string[] userOptions = { };
                            Dictionary<string, string> usercmd = Parse(args, userFlags, userOptions);
                            if(usercmd == null)
                            {
                                return;
                            }
                            usercmd.TryGetValue("--setspn", out aspn);
                            usercmd.TryGetValue("--removespn", out rspn);
                            usercmd.TryGetValue("--user", out user);
                            usercmd.TryGetValue("--password", out password);

                            if (aspn != null || rspn != null)
                            {
                                if(user == null)
                                {
                                    Console.WriteLine("[!] Please supply a value for the SPN and user account");
                                    return;
                                }
                                if(aspn != null && rspn != null)
                                {
                                    Console.WriteLine("[!] Cannot add and remove SPN at the same time");
                                    return;
                                }
                                if (aspn != null)
                                {
                                    Users.setSPN(aspn, user);
                                }
                                else if (rspn != null)
                                {
                                    Users.removeSPN(rspn, user);
                                }
                            }
                            else if (password != null)
                            {
                                if(user == null)
                                {
                                    Console.WriteLine("[!] Please supply a value for the user and password");
                                    return;
                                }
                                Users.changePassword(user, password);
                            }
                            break;
                        case "group":
                            string group = null;
                            string getmem = null;
                            string add = null;
                            string remove = null;

                            string[] groupFlags = {"--group", "--add", "--remove" };
                            string[] groupOptions = { "--getmembership" };
                            Dictionary<string, string> groupcmd = Parse(args, groupFlags, groupOptions);
                            if(groupcmd == null)
                            {
                                return;
                            }
                            groupcmd.TryGetValue("--getmembership", out getmem);
                            groupcmd.TryGetValue("--group", out group);
                            groupcmd.TryGetValue("--add", out add);
                            groupcmd.TryGetValue("--remove", out remove);

                            if (add != null)
                            {
                                if (group == null)
                                {
                                    Console.WriteLine("[!] Please supply a group");
                                    return;
                                }
                                Groups.AddToGroup(add, group);
                            }
                            else if (remove != null)
                            {
                                if (group == null)
                                {
                                    Console.WriteLine("[!] Please supply a group");
                                    return;
                                }
                                Groups.RemoveFromGroup(remove, group);
                            }
                            else if (getmem == "True")
                            {
                                if(group == null)
                                {
                                    Console.WriteLine("[!] Please supply a group");
                                    return;
                                }
                                Groups.GetGroupMembers(group);
                            }
                            else
                            {
                                Console.WriteLine("[!] Please specify an action");
                            }
                            break;

                        default:
                            Help();
                            break;
                    }
                }
                catch (IndexOutOfRangeException)
                {
                    Console.WriteLine("[!] Command invalid: use \"Cable.exe -h\" for more details");
                }
            }
            else
            {
                Console.WriteLine("[!] Cannot find module");
            }
        }
    }
}
