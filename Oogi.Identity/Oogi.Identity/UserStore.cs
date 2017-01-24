using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using DocumentDB.AspNet.Identity;
using Microsoft.AspNet.Identity;
using Microsoft.Azure.Documents.Client;
using Oogi.Query;

namespace Oogi.Identity
{
    public class UserStore<T> : IUserLoginStore<T>, IUserClaimStore<T>, IUserRoleStore<T>, IUserPasswordStore<T>, 
        IUserSecurityStampStore<T>, IUserStore<T>, IUserEmailStore<T>, IUserLockoutStore<T, string>, 
        IUserTwoFactorStore<T, string>, IUserPhoneNumberStore<T>, IQueryableUserStore<T, string>
        where T : IdentityUser, new()
    {
        private bool _disposed;
        private readonly Connection _connection;
        private readonly Repository<T> _repo = new Repository<T>();

        public UserStore()
        {            
            _connection = new Connection();
        }

        public UserStore(string endpoint, string authorizationKey, string database, string collection)
        {
            _connection = new Connection(endpoint, authorizationKey, database, collection);
        }        

        public async Task AddLoginAsync(T user, UserLoginInfo login)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            if (login == null)            
                throw new ArgumentNullException(nameof(login));            

            if (!user.Logins.Any(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey))
            {
                user.Logins.Add(login);
            }

            await _repo.ReplaceAsync(user);
        }

        public async Task<T> FindAsync(UserLoginInfo login)
        {
            ThrowIfDisposed();

            if (login == null)            
                throw new ArgumentNullException(nameof(login));

            // TODO: optimize
            var users = await _repo.GetAllAsync();

            return (from user in users from userLogin in user.Logins where userLogin.LoginProvider == login.LoginProvider && 
                    userLogin?.ProviderKey == userLogin.ProviderKey select user).FirstOrDefault();
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            return Task.FromResult(user.Logins.ToIList());
        }

        public Task RemoveLoginAsync(T user, UserLoginInfo login)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            if (login == null)            
                throw new ArgumentNullException(nameof(login));            

            user.Logins.Remove(u => u.LoginProvider == login.LoginProvider && u.ProviderKey == login.ProviderKey);

            return Task.FromResult(0);
        }

        public async Task CreateAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            await _repo.CreateAsync(user); 
        }

        public async Task DeleteAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var selectedUser = _repo.GetFirstOrDefault(user.Id);

            if (selectedUser != null)
            {
                await _repo.DeleteAsync(selectedUser);                
            }
        }

        public async Task<T> FindByIdAsync(string userId)
        {
            ThrowIfDisposed();

            if (userId == null)            
                throw new ArgumentNullException(nameof(userId));

            return await _repo.GetFirstOrDefaultAsync(userId);
        }

        public async Task<T> FindByNameAsync(string userName)
        {
            ThrowIfDisposed();

            if (userName == null)            
                throw new ArgumentNullException(nameof(userName));            
            
            var q = new DynamicQuery<T>
                (
                "select top 1 from c where c.entity = @entity and c.userName = @userName",
                new
                {
                    entity = Entity,
                    userName = userName
                }
                );

            return await _repo.GetFirstOrDefaultAsync(q);
        }

        public Task AddClaimAsync(T user, Claim claim)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            if (!user.Claims.Any(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value))
            {
                user.Claims.Add(new IdentityUserClaim
                {
                    ClaimType = claim.Type,
                    ClaimValue = claim.Value
                });
            }

            return Task.FromResult(0);
        }

        public Task<IList<Claim>> GetClaimsAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            IList<Claim> result = user.Claims.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList();
            return Task.FromResult(result);
        }

        public Task RemoveClaimAsync(T user, Claim claim)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            user.Claims.RemoveAll(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value);
            return Task.FromResult(0);
        }

        public Task AddToRoleAsync(T user, string roleName)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            if (roleName == null)            
                throw new ArgumentNullException(nameof(roleName));            

            if (!user.Roles.Any(x => x.Equals(roleName)))            
                user.Roles.Add(roleName);            

            return Task.FromResult(0);
        }

        public Task<IList<string>> GetRolesAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            var result = user.Roles.ToIList();

            return Task.FromResult(result);
        }

        public Task<bool> IsInRoleAsync(T user, string roleName)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            if (roleName == null)            
                throw new ArgumentNullException(nameof(roleName));            

            var isInRole = user.Roles.Any(x => x.Equals(roleName));

            return Task.FromResult(isInRole);
        }

        public Task RemoveFromRoleAsync(T user, string roleName)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            if (roleName == null)            
                throw new ArgumentNullException(nameof(roleName));            

            user.Roles.Remove(x => x.Equals(roleName));

            return Task.FromResult(0);
        }

        public Task<string> GetPasswordHashAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            return Task.FromResult(user.PasswordHash != null);
        }

        public Task SetPasswordHashAsync(T user, string passwordHash)
        {
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.PasswordHash = passwordHash;

            return Task.FromResult(0);
        }

        public Task<string> GetSecurityStampAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            return Task.FromResult(user.SecurityStamp);
        }

        public Task SetSecurityStampAsync(T user, string stamp)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            user.SecurityStamp = stamp;

            return Task.FromResult(0);
        }

        public async Task<T> FindByEmailAsync(string email)
        {
            ThrowIfDisposed();

            if (email == null)
            {
                throw new ArgumentNullException(nameof(email));
            }

            var q = new DynamicQuery<T>
                (
                "select top 1 from c where c.entity = @entity and c.email = @email",
                new
                {
                    entity = Entity,
                    email = email
                }
                );

            return await _repo.GetFirstOrDefaultAsync(q);
        }

        public Task<string> GetEmailAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            return Task.FromResult(user.EmailConfirmed);
        }

        public Task SetEmailAsync(T user, string email)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            if (email == null)            
                throw new ArgumentNullException(nameof(email));            

            user.Email = email;

            return Task.FromResult(0);
        }

        public Task SetEmailConfirmedAsync(T user, bool confirmed)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            user.EmailConfirmed = confirmed;

            return Task.FromResult(0);
        }

        public Task<int> GetAccessFailedCountAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<bool> GetLockoutEnabledAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            return Task.FromResult(user.LockoutEnabled);
        }

        public Task<DateTimeOffset> GetLockoutEndDateAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.LockoutEnd);
        }

        public Task<int> IncrementAccessFailedCountAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            user.AccessFailedCount++;

            return Task.FromResult(user.AccessFailedCount);
        }

        public Task ResetAccessFailedCountAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            user.AccessFailedCount = 0;

            return Task.FromResult(0);
        }

        public Task SetLockoutEnabledAsync(T user, bool enabled)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            user.LockoutEnabled = enabled;

            return Task.FromResult(0);
        }

        public Task SetLockoutEndDateAsync(T user, DateTimeOffset lockoutEnd)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            user.LockoutEnd = lockoutEnd;

            return Task.FromResult(0);
        }

        public Task<bool> GetTwoFactorEnabledAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            return Task.FromResult(user.TwoFactorEnabled);
        }

        public Task SetTwoFactorEnabledAsync(T user, bool enabled)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            user.TwoFactorEnabled = enabled;

            return Task.FromResult(0);
        }

        public Task<string> GetPhoneNumberAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task SetPhoneNumberAsync(T user, string phoneNumber)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            if (phoneNumber == null)            
                throw new ArgumentNullException(nameof(phoneNumber));            

            user.PhoneNumber = phoneNumber;

            return Task.FromResult(0);
        }

        public Task SetPhoneNumberConfirmedAsync(T user, bool confirmed)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));            

            user.PhoneNumberConfirmed = confirmed;

            return Task.FromResult(0);
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }

        public void Dispose()
        {
            _disposed = true;
        }

        public async Task UpdateAsync(T user)
        {
            ThrowIfDisposed();

            if (user == null)            
                throw new ArgumentNullException(nameof(user));

            await _repo.ReplaceAsync(user);
        }

        private string Entity { get; } = new T().Entity;

        private Uri DocumentCollectionUri => UriFactory.CreateDocumentCollectionUri(_connection.DatabaseId, _connection.CollectionId);
       
        public IQueryable<T> Users => _connection.Client.CreateDocumentQuery<T>(DocumentCollectionUri);
    }
}