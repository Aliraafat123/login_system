using ForgotPassword2.Controllers.Models;
using ForgotPassword2.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace ForgotPassword2.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }
        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _authService.RegisterAsync(model);
            if (!result.IsAuthenticated)
                return BadRequest(result.Message);
            return Ok(new { token = result.Token, expireson = result.ExpiresOn });
        }
        [HttpPost("Login")]
        public async Task<IActionResult> GetTokenAsync([FromBody] LoginModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.LoginAsync(model);

            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            return Ok(new { token = result.Token, expireson = result.ExpiresOn });
        }
        [HttpPost ]
        [Route("forgotPassword")]
        public async Task<IActionResult> ForgotPassword( [FromBody ]PasswordResetRequest request)
        {
            var user = await _authService.GetUserByEmail(request.Email);
            if (user != null)
            {

                var resetToken = GenerateUniqueToken();
                user.ResetToken = resetToken;
                user.ResetTokenExpiry = DateTime.UtcNow.AddHours(1);
                await _authService.UpdateUser(user);
                _authService.SendEmail("lrft205@gmail.com", "ABC123");
                return Ok("Password reset instructions to your email.");
            }
            return BadRequest("User with this Email does not exist.");
        }

        private string? GenerateUniqueToken()
        {
            string timestamp = DateTime.UtcNow.ToString("MMddyyyyHHmmss");
            string randomPart= Guid.NewGuid().ToString().Substring(0, 4);
            string resetcode = timestamp + randomPart;
            return resetcode;
        }

        [HttpPost]
        [Route("resetpassword")]
        public async Task <IActionResult > Resetpassword([FromBody] PasswordResetModel model)
        {
            var user = await _authService.GetUserByResetToken(model.Email, model.ResetToken);
            if (user != null && user .ResetTokenExpiry >DateTime.UtcNow ) 
            {

                user.Password = HashPassword(model.NewPassword);
                user.ResetToken = null;

                user.ResetTokenExpiry = DateTime.UtcNow.AddHours(1);

                await _authService.UpdateUser(user);
                return Ok("password reset successfully.");
                
            }
            return BadRequest("invalid or expired reset token");
        }

        private string? HashPassword(string? resetCode)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(resetCode));
                return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
            }
        }
        
    }


}

