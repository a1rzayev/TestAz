using Microsoft.AspNetCore.Mvc;
using TestAzAPI.Models;
using TestAzAPI.Models.Dtos;
using TestAzAPI.Repositories.Base;
using TestAzAPI.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;


namespace TestAzAPI.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IUserRepository _userRepo;
    private readonly IConfiguration _config;
    private readonly JwtService _jwtService;

    public AuthController(IUserRepository userRepo, IConfiguration config, JwtService jwtService)
    {
        _userRepo = userRepo;
        _config = config;
        _jwtService = jwtService;
    }


    [HttpPost("signup")]
    public async Task<IActionResult> Signup(SignupDto dto)
    {
        if (await _userRepo.ExistsAsync(dto.Email))
            return BadRequest("User already exists");

        PasswordService.CreatePasswordHash(dto.Password, out var hash, out var salt);

        var user = new User
        {
            Email = dto.Email,
            PasswordHash = hash,
            PasswordSalt = salt
        };

        await _userRepo.AddAsync(user);
        await _userRepo.SaveChangesAsync();

        return Ok(new { message = "User registered" });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginDto login)
    {
        var user = await _userRepo.GetByEmailAsync(login.Email);
        if (user == null || !PasswordService.VerifyPassword(login.Password, user.PasswordHash, user.PasswordSalt))
            return Unauthorized("Invalid credentials");
        var token = _jwtService.GenerateJwtToken(user);

        return Ok(new { token, user.Id, user.Email });
    }
}
