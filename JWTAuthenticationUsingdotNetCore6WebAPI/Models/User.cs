namespace JWTAuthenticationUsingdotNetCore6WebAPI.Models
{
    public class User
    {
        public string UserName { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
        public byte[]  PasswordHash { get; set; }
        public byte[]  PasswordSalt { get; set; }
               

    }
}
