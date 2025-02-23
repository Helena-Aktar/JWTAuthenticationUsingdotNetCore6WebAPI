﻿using JWTAuthenticationUsingdotNetCore6WebAPI.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JWTAuthenticationUsingdotNetCore6WebAPI.Services.UserServices
{
    public class UserService : IUserService
    {
        private readonly IHttpContextAccessor _httpContextAccessor;


        public UserService(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }
        public object getUser()
        {
           UserDto user = new UserDto();
            if(_httpContextAccessor.HttpContext!=null)
            {
                user.UserName = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
                user.Role = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Role);
           
            }
            return user;

        }
     
    }
}
