using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Mail;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;

namespace Oogi.Identity
{
    public class SmartUserValidator : UserValidator<IdentityUser>
    {
        public UserManager<IdentityUser> Manager { get; }

        /// <summary>
        /// Error messages configuration.
        /// </summary>
        public Messages Messages { get; set; }

        public SmartUserValidator(UserManager<IdentityUser> manager, Messages messages = null) : base(manager)
        {
            Manager = manager;
            Messages = messages ?? new Messages();
        }

        public override async Task<IdentityResult> ValidateAsync(IdentityUser item)
        {
            if (item == null)
            {
                throw new ArgumentNullException(nameof(item));
            }

            var errors = new List<string>();
            await ValidateUserNameAsync(item, errors);

            if (RequireUniqueEmail)
            {
                await ValidateEmailAsync(item, errors);
            }
            if (errors.Count > 0)
            {
                return IdentityResult.Failed(errors.ToArray());
            }
            return IdentityResult.Success;
        }

        private async Task ValidateUserNameAsync(IdentityUser user, List<string> errors)
        {
            if (string.IsNullOrWhiteSpace(user.UserName))
            {
                errors.Add(Messages.UserNameTooShort);
            }
            else if (AllowOnlyAlphanumericUserNames && 
                !Regex.IsMatch(user.UserName, @"^[A-Za-z0-9@_\.]+$"))
            {
                errors.Add(string.Format(CultureInfo.CurrentCulture, Messages.InvalidUserName, user.UserName));                
            }
            else
            {                
                var owner = await Manager.FindByNameAsync(user.UserName);
                if (owner != null && 
                    !EqualityComparer<string>.Default.Equals(owner.Id, user.Id))
                {
                    errors.Add(string.Format(CultureInfo.CurrentCulture, Messages.DuplicateName, user.UserName));                    
                }
            }
        }

        private async Task ValidateEmailAsync(IdentityUser user, List<string> errors)
        {                        
            if (string.IsNullOrWhiteSpace(user.Email))
            {                
                errors.Add(Messages.EmailTooShort);
                return;
            }
            try
            {
                var m = new MailAddress(user.Email);
            }
            catch (FormatException)
            {
                errors.Add(string.Format(CultureInfo.CurrentCulture, Messages.InvalidEmail, user.Email));                
                return;
            }
            var owner = await Manager.FindByEmailAsync(user.Email);

            if (owner != null && !EqualityComparer<string>.Default.Equals(owner.Id, user.Id))
            {
                errors.Add(string.Format(CultureInfo.CurrentCulture, Messages.DuplicateEmail, user.Email));                
            }
        }
    }
}
