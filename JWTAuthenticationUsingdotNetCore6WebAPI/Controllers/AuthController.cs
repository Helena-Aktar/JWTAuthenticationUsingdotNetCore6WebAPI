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
        private readonly IUserService _userService;

        public AuthController(IConfiguration configuration,IUserService userService)
        {
            _configuration = configuration;
            _userService = userService;
        }
        [HttpGet("getUserInfo"),Authorize]
        public IActionResult GetMe()
        {
            //without using userService and interface
            //User user = new User();
            //user.UserName = User?.Identity?.Name;
            //var claimName = User.FindFirstValue(ClaimTypes.Name);
            //var claimRole = User.FindFirstValue(ClaimTypes.Role);
            //return Ok(new{ user, claimName, claimRole });

            object user = _userService.getUser();
            return Ok(new { user });
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto req)
        {
            CreatePasswordHash(req.Password, out byte[] passwordHash, out byte[] passwordSalt);
            user.UserName= req.UserName;
            user.PasswordHash= passwordHash;
            user.PasswordSalt= passwordSalt;
      //dont return passwordHash and passwordSalt while Working IRL
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
            var refreshToken = GenerateRefreshToken();
            SetRefreshToken(refreshToken);
            return Ok(new { req.UserName,token});
        }
        [HttpPost("refreshToken")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            string tokenExpiresString = user.RefTokenExpires.ToString();
            Console.WriteLine(tokenExpiresString);
            var refreshToken = Request.Cookies["refreshToken"];
            Console.WriteLine(refreshToken);

            if (user.RefTokenExpires < DateTime.UtcNow)
            {
                return Unauthorized("Token expired.");
            }
            else if(!user.RefreshToken.Equals(refreshToken))
            {
                return Unauthorized("Invalid Refresh Token.");
            }
           

            string token = CreateToken(user);
            var newRefreshToken = GenerateRefreshToken();
            SetRefreshToken(newRefreshToken);
            Console.Write(user);
            return Ok(token);
        }

        // helper methods



        private RefreshToken GenerateRefreshToken()
        {

            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow
            };

            return refreshToken;
        }

        private void SetRefreshToken(RefreshToken newRefreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefreshToken.Expires
            };
            Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

            user.RefreshToken = newRefreshToken.Token;
            user.RefTokenCreated = newRefreshToken.Created;
            user.RefTokenExpires = newRefreshToken.Expires;
        }


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
