using ForgotPassword2.Controllers.Models;

namespace ForgotPassword2.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterModel model);
        Task<AuthModel> LoginAsync(LoginModel model);

        Task <User> GetUserByEmail(string email);
        Task UpdateUser(User user);

        Task <User >GetUserByResetToken (string email,string resetToken);

        Task SendEmail(string toEmail, string resetToken);
    }
}
