using System;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Oogi;
using Oogi.Identity;

namespace Tests
{
    [TestClass]
    public class UserStoreTests 
    {
        public class SuperIdentityUser : IdentityUser
        {
            public override string Entity { get; set; } = "oogi.identity";
        }

        private readonly UserStore<SuperIdentityUser> _userStore = new UserStore<SuperIdentityUser>();
        
        [TestMethod]
        public async Task CreateUserAsync()
        {
            var testUser = new SuperIdentityUser
            {
                UserName = "test-user-1",
                Email = "test.user.1@test.com"
            };

            await _userStore.CreateAsync(testUser);

            var savedUser = await _userStore.FindByEmailAsync(testUser.Email);

            Assert.IsNotNull(savedUser);
            Assert.AreEqual(testUser.Email, savedUser.Email);
        }

        [TestMethod]
        public async Task UpdatesAreAppliedToUser()
        {
            var testUser = new SuperIdentityUser
            {
                UserName = "test-user-2",
                Email = "test.user.2@test.com"                
            };

            await _userStore.CreateAsync(testUser);

            var savedUser = await _userStore.FindByEmailAsync(testUser.Email);

            if (savedUser == null)            
                throw new NullReferenceException("savedUser");            

            savedUser.EmailConfirmed = true;

            await _userStore.UpdateAsync(savedUser);

            savedUser = await _userStore.FindByEmailAsync(testUser.Email);

            Assert.IsNotNull(savedUser);
            Assert.IsTrue(savedUser.EmailConfirmed);
        }

        [TestMethod]
        public async Task UsersWithCustomIdsPersistThroughStorageAsync()
        {
            var testUser = new SuperIdentityUser
            {
                UserName = "test-user-3",
                Email = "test.user.3@test.com",
                Id = "test-user-id-3"                
            };
            
            await _userStore.CreateAsync(testUser);

            var savedUser = await _userStore.FindByEmailAsync(testUser.Email);

            Assert.IsNotNull(savedUser);
            Assert.AreEqual(testUser.Id, savedUser.Id);
        }

        [TestMethod]
        public async Task UsersWithNoSetIdDefaultToNewGuidAsync()
        {
            var testUser = new SuperIdentityUser
            {
                UserName = "test-user-4",
                Email = "test.user.4@test.com"                
            };

            await _userStore.CreateAsync(testUser);

            var savedUser = await _userStore.FindByEmailAsync(testUser.Email);
            Assert.IsTrue(!string.IsNullOrEmpty(savedUser.Id));

            Guid guidId;
            Assert.IsTrue(Guid.TryParse(savedUser.Id, out guidId));
        }

        [TestMethod]
        public async Task CanFindUserByLoginInfoAsync()
        {
            var testUser = new SuperIdentityUser
            {
                UserName = "test-user-5",
                Email = "test.user.5@test.com"                
            };

            await _userStore.CreateAsync(testUser);

            var user = await _userStore.FindByEmailAsync(testUser.Email);
            Assert.IsNotNull(user);

            var loginInfo = new UserLoginInfo("ATestLoginProvider", "ATestKey292929");
            await _userStore.AddLoginAsync(user, loginInfo);

            var userByLoginInfo = await _userStore.FindAsync(loginInfo);

            Assert.IsNotNull(userByLoginInfo);
        }

        [TestCleanup]
        public async Task DeleteRobotsAsync()
        {
            var repo = new Repository<SuperIdentityUser>();

            var users = repo.GetAll();

            foreach (var user in users)
            {
                await repo.DeleteAsync(user);
            }
        }
    }
}
