
global using JWTAuthenticationUsingdotNetCore6WebAPI.Services.UserServices;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
//injecting user uservices
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddHttpContextAccessor();
// gives ui for putting token 
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        Description = "Standard Authorization header using the Bearer scheme (\"bearer {token}\")",
        In = ParameterLocation.Header,
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey
    });

    options.OperationFilter<SecurityRequirementsOperationFilter>();
});

//Adding jwt authenticationScheme 
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8
                .GetBytes(builder.Configuration.GetSection("AppSettings:Token").Value)),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero // cancels out the 5min  delay of library
        };
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                // Try to get the token from the "accessToken" cookie
                if (context.Request.Cookies.ContainsKey("accessToken"))
                {
                    context.Token = context.Request.Cookies["accessToken"];
                }
                return Task.CompletedTask;
            }
        };
    });

//builder.Services.AddAuthentication(options =>
//{
//    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
//    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
//})
//.AddJwtBearer(options =>
//{
//    options.TokenValidationParameters = new TokenValidationParameters
//    {
//        ValidateIssuerSigningKey = true,
//        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8
//                        .GetBytes(builder.Configuration.GetSection("AppSettings:Token").Value)),
//        ValidateIssuer = false,
//        ValidateAudience = false,
//        ValidateLifetime = true,
//        ClockSkew = TimeSpan.Zero // cancels out the 5min  delay of library
//    };
//    options.Events = new JwtBearerEvents
//    {
//        OnMessageReceived = context =>
//        {
//            // Try to get the token from the "accessToken" cookie
//            if (context.Request.Cookies.ContainsKey("accessToken"))
//            {
//                context.Token = context.Request.Cookies["accessToken"];
//            }
//            return Task.CompletedTask;
//        }
//    };
//});
//.AddCookie(options =>
//{
//    options.Cookie.Name = "accessToken";
//    options.Events = new CookieAuthenticationEvents
//    {
//        OnValidatePrincipal = context =>
//        {
//            // Your custom validation logic here
//            return Task.CompletedTask;
//        }
//    };
//});



var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication(); //for jwt  must add above UseAuthorization()

app.UseAuthorization();

app.MapControllers();

app.Run();
