using System;
using System.Linq;
using System.DirectoryServices.ActiveDirectory;

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
                Console.WriteLine("Forest: "+ controller.Forest);
                Console.WriteLine("IP: " + controller.IPAddress);
                Console.WriteLine("Version: " + controller.OSVersion + "\n");
            }            
        }

        static void users()
        {
            
        }

        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                if(args.Contains("--help") || args.Contains("-h"))
                {
                    Help();
                }
                else if (args.Contains("dclist"))
                {
                    dclist(); 
                }
            }
            else
            {
                Console.WriteLine("Please supply a command - Use \"--help\" for a list of commands");
            }
        }
    }
}
