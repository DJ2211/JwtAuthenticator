using MailKit;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using JwtAuthenticator.Options;
using Microsoft.Extensions.Options;

namespace JwtAuthenticator.Services;
public class EmailSender : IEmailSender
{
    private readonly ILogger<EmailSender> _logger;
    private readonly EmailOptions _emailOptions;

    public EmailSender(ILogger<EmailSender> logger, IOptions<EmailOptions> emailOptions)
    {
        _logger = logger;
        _emailOptions = emailOptions.Value;
    }

    public async Task SendEmailAsync(string toEmail, string subject, string message)
    {
        if(_emailOptions.Provider.Equals("smtp", StringComparison.OrdinalIgnoreCase))
        {
            await SendViaSmtpAsync(toEmail, subject, message);
            return;
        }

        // In local development, log to console.
        // In production, plug in SendGrid, Resend, AWS SES, or SMTP here.
        _logger.LogInformation("================ EMAIL DISPATCH ================");
        _logger.LogInformation("To: {ToEmail}", toEmail);
        _logger.LogInformation("Subject: {Subject}", subject);
        _logger.LogInformation("Content: {Message}", message);
        _logger.LogInformation("===============================================");
    }

    private async Task SendViaSmtpAsync(string toEmail, string subject, string message)
    {
        var email = new MimeMessage();
        email.From.Add(new MailboxAddress(_emailOptions.FromName, _emailOptions.FromEmail));
        email.To.Add(MailboxAddress.Parse(toEmail));
        email.Subject = subject;
        email.Body = new TextPart("plain") { Text = message };

        using var smtp = new SmtpClient();
        var socketOptions = _emailOptions.UseSsl ? SecureSocketOptions.Auto : SecureSocketOptions.None;

        await smtp.ConnectAsync(_emailOptions.SmtpHost, _emailOptions.SmtpPort, socketOptions);

        if(!string.IsNullOrWhiteSpace(_emailOptions.Username))
        {
            await smtp.AuthenticateAsync(_emailOptions.Username, _emailOptions.Password ?? string.Empty);
        }

        await smtp.SendAsync(email);
        await smtp.DisconnectAsync(true);
    }


}
