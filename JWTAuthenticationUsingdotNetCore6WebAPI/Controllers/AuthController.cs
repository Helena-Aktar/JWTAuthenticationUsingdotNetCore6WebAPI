using JWTAuthenticationUsingdotNetCore6WebAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Unicode;

namespace JWTAuthenticationUsingdotNetCore6WebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();

        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        [HttpGet("getUserInfo"),Authorize]
        public IActionResult GetMe()
        {
            User user = new User();
            user.UserName = User?.Identity?.Name;
            var claimName = User.FindFirstValue(ClaimTypes.Name);
            var claimRole = User.FindFirstValue(ClaimTypes.Role);
            return Ok(new{ user, claimName, claimRole });
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto req)
        {
            CreatePasswordHash(req.Password, out byte[] passwordHash, out byte[] passwordSalt);
            user.UserName= req.UserName;
            user.PasswordHash= passwordHash;
            user.PasswordSalt= passwordSalt;
      
            return Ok(new {user});
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
            string token = CreateToken(user);
            return Ok(new { req.UserName,token});
        }

       
        // helper methods
        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
            new Claim(ClaimTypes.Name,user.UserName),
            new Claim(ClaimTypes.Role,"Admin"),

            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));
            var cred = new SigningCredentials(key,SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: cred
                );
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }




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
