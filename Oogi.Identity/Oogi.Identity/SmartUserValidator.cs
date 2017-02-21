using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Mail;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;

namespace Oogi.Identity
{
    // TODO: handle if messages is null
    public class SmartUserValidator<TUser> : SmartUserValidator<TUser, string> where TUser : class, IUser<string>
    {
        /// <summary>
        /// Ctor.
        /// </summary>        
        public SmartUserValidator(UserManager<TUser, string> manager) : base(manager)
        {
        }
    }

    public class SmartUserValidator<TUser, TKey> : IIdentityValidator<TUser>
        where TUser : class, IUser<TKey>
        where TKey : IEquatable<TKey>
    {
        public UserManager<TUser, TKey> Manager { get; }
        public bool AllowOnlyAlphanumericUserNames { get; set; }
        public bool RequireUniqueEmail { get; set; }

        /// <summary>
        /// Error messages configuration.
        /// </summary>
        public Messages Messages { get; set; }

        public SmartUserValidator(UserManager<TUser, TKey> manager, Messages messages = null) 
        {
            Manager = manager;
            Messages = messages ?? new Messages();
        }

        public async Task<IdentityResult> ValidateAsync(TUser item)
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

            return errors.Count > 0 ? IdentityResult.Failed(errors.ToArray()) : IdentityResult.Success;
        }        

        private async Task ValidateUserNameAsync(TUser user, ICollection<string> errors)
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
                    !EqualityComparer<TKey>.Default.Equals(owner.Id, user.Id))
                {
                    errors.Add(string.Format(CultureInfo.CurrentCulture, Messages.DuplicateName, user.UserName));
                }
            }
        }        

        private async Task ValidateEmailAsync(TUser user, ICollection<string> errors)
        {
            var iu = user as IdentityUser;
            var email = user.UserName;

            if (iu != null)
                email = iu.Email;            

            if (string.IsNullOrWhiteSpace(email))
            {
                errors.Add(Messages.EmailTooShort);
                return;
            }

            try
            {
                var m = new MailAddress(email);
            }
            catch (FormatException)
            {
                errors.Add(string.Format(CultureInfo.CurrentCulture, Messages.InvalidEmail, email));
                return;
            }

            var owner = await Manager.FindByEmailAsync(email);

            if (owner != null && !EqualityComparer<TKey>.Default.Equals(owner.Id, user.Id))
            {
                errors.Add(string.Format(CultureInfo.CurrentCulture, Messages.DuplicateEmail, email));
            }
        }        
    }
}
