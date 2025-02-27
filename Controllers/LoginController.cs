using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using dvcsharp_core_api.Models;
using dvcsharp_core_api.Data;

namespace purchasepal_core
{
    class PurchaseController
    {
        static void Main(string[] args)
        {
            try
            {
                var user = args[0];
                var pwd = Encrypt(args[1]);
                Login(user, pwd);
            }
            catch  
            {

                Console.WriteLine("An error has occurred!!");
            }
            
        }

        private static  string Encrypt(string plain)
        {
            return plain;
        }

        private static void Login(string username,string password)
        {
            try
            {
                using (var conn = new SqlConnection("conn..."))
                {
                    var sql = "SELECT * FROM Users WHERE username = '" + username + "' AND pwd = '" + password + "'";
                    using (var cmd = new SqlCommand(sql))
                    {
                        cmd.Connection = conn;
                        cmd.ExecuteScalar();
                    }

                }
            }
            catch  
            {

                Console.WriteLine("An error has occurred !!");
            }
           
        }
    }
}
