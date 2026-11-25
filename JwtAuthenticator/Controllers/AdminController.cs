using JwtAuthenticator.Constants;
using JwtAuthenticator.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthenticator.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = Roles.Admin)]
    public class AdminController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public AdminController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        [HttpGet("users")]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _userManager.Users.Select(u => new
            {
                u.Id,
                u.Email,
                u.FirstName,
                u.LastName,
                u.EmailConfirmed,
                u.CreatedAtUtc
            }).ToListAsync();

            return Ok(users);
        }

        [HttpPost("promote")]
        public async Task<IActionResult> PromoteToAdmin([FromQuery] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user is null)
            {
                return Problem(title: "Not found", detail: "User not found.", statusCode: StatusCodes.Status404NotFound);
            }

            if(await _userManager.IsInRoleAsync(user, Roles.Admin))
            {
                return Ok(new { message = $"User '{email}' is already an Admin." });
            }

            await _userManager.AddToRoleAsync(user, Roles.Admin);
            return Ok(new { message = $"User '{email}' promoted to Admin successfully." });
        }
    }
}
