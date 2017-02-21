using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;

namespace Oogi.Identity
{
    public class SmartPasswordValidator : IIdentityValidator<string>
    {
        /// <summary>
        /// Error messages configuration.
        /// </summary>
        public Messages Messages { get; }

        /// <summary>
        /// Minimum required length
        /// </summary>
        public int RequiredLength { get; set; }

        /// <summary>
        ///  Require a non letter or digit character
        /// </summary>
        public bool RequireNonLetterOrDigit { get; set; }

        /// <summary>
        ///     Require a lower case letter ('a' - 'z')
        /// </summary>
        public bool RequireLowercase { get; set; }

        /// <summary>
        ///     Require an upper case letter ('A' - 'Z')
        /// </summary>
        public bool RequireUppercase { get; set; }

        /// <summary>
        ///     Require a digit ('0' - '9')
        /// </summary>
        public bool RequireDigit { get; set; }


        public PasswordValidator(Messages messages = null)
        {
            Messages = messages;
        }

        /// <summary>
        /// Ensures that the string is of the required length and meets the configured requirements.
        /// </summary>
        public virtual Task<IdentityResult> ValidateAsync(string item)
        {
            if (item == null)            
                throw new ArgumentNullException(nameof(item));
            
            var errors = new List<string>();

            if (string.IsNullOrWhiteSpace(item) || 
                item.Length < RequiredLength)            
                errors.Add(string.Format(CultureInfo.CurrentCulture, Messages.PasswordTooShort, RequiredLength));
            
            if (RequireNonLetterOrDigit && 
                item.All(IsLetterOrDigit))            
                errors.Add(Messages.PasswordRequireNonLetterOrDigit);

            if (RequireDigit && 
                item.All(c => !IsDigit(c)))
                errors.Add(Messages.PasswordRequireDigit);

            if (RequireLowercase && 
                item.All(c => !IsLower(c)))
                errors.Add(Messages.PasswordRequireLower);

            if (RequireUppercase &&
                item.All(c => !IsUpper(c)))
                errors.Add(Messages.PasswordRequireUpper);

            return Task.FromResult(errors.Count == 0 ? IdentityResult.Success : IdentityResult.Failed(string.Join(" ", errors)));
        }

        /// <summary>
        ///  Returns true if the character is a digit between '0' and '9'.
        /// </summary>
        protected virtual bool IsDigit(char c)
        {
            return c >= '0' && c <= '9';
        }

        /// <summary>
        /// Returns true if the character is between 'a' and 'z'
        /// </summary>
        protected virtual bool IsLower(char c)
        {
            return c >= 'a' && c <= 'z';
        }

        /// <summary>
        /// Returns true if the character is between 'A' and 'Z'.
        /// </summary>
        protected virtual bool IsUpper(char c)
        {
            return c >= 'A' && c <= 'Z';
        }

        /// <summary>
        /// Returns true if the character is upper, lower, or a digit
        /// </summary>
        protected virtual bool IsLetterOrDigit(char c)
        {
            return IsUpper(c) || IsLower(c) || IsDigit(c);
        }
    }
}