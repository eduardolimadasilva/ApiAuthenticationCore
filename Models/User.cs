
using Microsoft.AspNetCore.Identity;

namespace TodoApi.Models
{
    public class ApplicationUser : IdentityUser { }
    public class User
    {
        public int Id { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
    }
    public static class Roles
    {
        public const string ROLE_API = "Acesso-API";
    }
    public class TokenConfigurations
    {
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public int Seconds { get; set; }
    }
}