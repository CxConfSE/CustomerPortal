using System;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Text;
using System.Security.Claims;
using dvcsharp_core_api.Data;

namespace dvcsharp_core_api.Models
{
   public class User
   {
      public const string RoleUser = "User";
      public const string RoleSupport = "Support";
      public const string RoleAdministrator = "Administrator";
      public const string TokenSecret = "f449a71cff1d56a122c84fa478c16af9075e5b4b8527787b56580773242e40ce";

      public int ID { get; set; }

      [Required]
      public string name { get; set; }
      [Required]
      public string email { get; set; }
      [Required]
      public string role { get; set; }
      [Required]
      [System.Runtime.Serialization.IgnoreDataMember]
      public string password { get; set; }
      [Required]
      public DateTime createdAt { get; set; }
      [Required]
      public DateTime updatedAt { get; set; }

      public void updatePassword(string password)
      {
         this.password = getHashedPassword(password);
      }

      public string createAccessToken()
      {
         string secret = TokenSecret;
         string issuer = "http://localhost.local/";
         string audience = "http://localhost.local/";

         var claims = new[]
         {
            new Claim("name", this.email),
            new Claim("role", this.role)
         };

         var signingKey = new Microsoft.IdentityModel.
            Tokens.SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));

         var creds = new Microsoft.IdentityModel.
            Tokens.SigningCredentials(signingKey, 
               Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256);

         var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            expires: DateTime.Now.AddMinutes(30),
            claims: claims,
            signingCredentials: creds
         );

         return (new System.IdentityModel.Tokens.
            Jwt.JwtSecurityTokenHandler().WriteToken(token));
      }

      public static string GetHashedPassword(string password)
      {
          // Generate a random salt
          byte[] salt = new byte[16];
          using (var rng = RandomNumberGenerator.Create())
          {
              rng.GetBytes(salt);
          }
      
          // Derive the key
          using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256))
          {
              byte[] hash = pbkdf2.GetBytes(32);
      
              // Combine salt + hash for storage
              byte[] hashBytes = new byte[48];
              Array.Copy(salt, 0, hashBytes, 0, 16);
              Array.Copy(hash, 0, hashBytes, 16, 32);
      
              // Return as base64 string
              return Convert.ToBase64String(hashBytes);
          }
      }

      public static AuthorizationResponse authorizeCreateAccessToken(GenericDataContext _context, 
         AuthorizationRequest authorizationRequest)
      {
         AuthorizationResponse response = null;

         User user = _context.Users.
            Where(b => b.email == authorizationRequest.email).
            FirstOrDefault();
         
         if(user == null) {
            return response;
         }

         if(getHashedPassword(authorizationRequest.password) != user.password) {
            return response;
         }

         response = new AuthorizationResponse();
         response.role = user.role;
         response.accessToken = user.createAccessToken();

         return response;
      }
   }
}
