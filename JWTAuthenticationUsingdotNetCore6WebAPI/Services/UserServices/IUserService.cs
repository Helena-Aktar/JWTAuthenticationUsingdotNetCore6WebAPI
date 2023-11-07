using Microsoft.AspNetCore.Mvc;
using JWTAuthenticationUsingdotNetCore6WebAPI.Models;
namespace JWTAuthenticationUsingdotNetCore6WebAPI.Services.UserServices
{
    
    public interface IUserService 
    {
        //User User = new User();
        Object getUser();
    }
}
