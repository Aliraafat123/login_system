using ForgotPassword2.Controllers.Models;
using ForgotPassword2.Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Mail;
using System.Net;
using System.Security.Claims;
using System.Text;

namespace ForgotPassword2.Services
{
    public class AuthService:IAuthService
    {
        
        private readonly EmailConfiguration _configuration;
        private readonly ApplicationDbContext _context;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JWT _jwt;
        public AuthService(UserManager<IdentityUser> userManager, IOptions<JWT> jwt, ApplicationDbContext context )
        {
            _userManager = userManager;
            _jwt = jwt.Value;
            _context = context;
            
        }

        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            if (await _userManager.FindByEmailAsync(model.Email) is not null)
                return new AuthModel { Message = "Email Is Already Registered !" };
            var User = new IdentityUser
            {
                Email = model.Email,
                UserName = model.Email,
                PhoneNumber = model.phoneNumber
            };
            var result = await _userManager.CreateAsync(User, model.Password);
            if (!result.Succeeded)
            {
                var errors = string.Empty;
                foreach (var error in result.Errors)
                {
                    errors += $"{error.Description} ,";
                }
                return new AuthModel { Message = errors };
            }
            await _userManager.AddToRoleAsync(User, "User");
            var jwtsecuritytoken = await CreateJwtToken(User);
            return new AuthModel
            {
                Email = User.Email,
                PhoneNumber = User.PhoneNumber,
                ExpiresOn = jwtsecuritytoken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtsecuritytoken),
            };
        }
        public async Task<AuthModel> LoginAsync(LoginModel model)
        {
            var authModel = new AuthModel();

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                authModel.Message = "Email or Password Is Incorrect!";
                return authModel;
            }
            var JwtSecurityToken = await CreateJwtToken(user);
            var rolesList = await _userManager.GetRolesAsync(user);

            authModel.IsAuthenticated = true;
            authModel.ExpiresOn = JwtSecurityToken.ValidTo;
            authModel.Email = user.Email;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(JwtSecurityToken);
            authModel.Roles = rolesList.ToList();

            return authModel;
        }
        private async Task<JwtSecurityToken> CreateJwtToken(IdentityUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays((double) _jwt.DurationInDays),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }

        public async Task<User> GetUserByEmail(string email)
        {
            return await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
        }

        public async Task UpdateUser(User user)
        {
            _context.Users.Update(user);
             await _context.SaveChangesAsync();
        }

        public async Task<User> GetUserByResetToken(string email, string resetToken)
        {
            return await _context.Users.FirstOrDefaultAsync (u=>u.Email==email&& u.ResetToken ==resetToken);
        }

        public async Task  SendEmail(string toEmail, string resetToken)
        {

            using (SmtpClient client = new SmtpClient(_configuration.SmtpServer, _configuration.Port))
            {
                client.UseDefaultCredentials = false;

                client.Credentials = new NetworkCredential(_configuration.UserName, _configuration.Password);

                client.EnableSsl = _configuration.UseSsl;

                MailMessage mailMessage = new MailMessage();

                mailMessage.From = new MailAddress(_configuration.DefaultSEnderEmail);

                mailMessage.To.Add(toEmail);

                mailMessage.Subject = "Password reset instructions";
                mailMessage.Body = $"please use the folloig token to resetyour password: {resetToken}";
                client.Send(mailMessage);
            }

        }


    }
}
