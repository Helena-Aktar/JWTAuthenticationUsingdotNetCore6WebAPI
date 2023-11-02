using JWTAuthenticationUsingdotNetCore6WebAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text.Unicode;

namespace JWTAuthenticationUsingdotNetCore6WebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto req)
        {
            CreatePasswordHash(req.Password, out byte[] passwordHash, out byte[] passwordSalt);
         user.UserName= req.UserName;
            user.PasswordHash= passwordHash;
            user.PasswordSalt= passwordSalt;
            
            return Ok(new {user });
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto req)
        {
            if (user.UserName != req.UserName)
            {
                return BadRequest("User not found");
            }
            else if(!VerifyPasswordHash(req.Password, user.PasswordHash,user.PasswordSalt))
            {
                return BadRequest("Wrong Password!");
            }
            return Ok(new { req.UserName});
        }

        // helper methods
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using(var hmac= new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using(var hmac= new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));

                return computedHash.SequenceEqual(passwordHash);
            }
        }


    }
}
