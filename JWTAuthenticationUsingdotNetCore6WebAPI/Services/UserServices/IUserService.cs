using Microsoft.AspNetCore.Mvc;

namespace JWTAuthenticationUsingdotNetCore6WebAPI.Services.UserServices
{
    public interface IUserService 
    {
        IActionResult getUserInfo();
    }
}
