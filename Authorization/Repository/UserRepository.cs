using Authorization.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authorization.Repository
{
    public class UserRepository
    {
        private List<User> TestUsers;
        public UserRepository()
        {
            TestUsers = new List<User>();
            TestUsers.Add(new User() { Username = "Test1", Password = "Pass1" });
            TestUsers.Add(new User() { Username = "Test2", Password = "Pass2" });
            TestUsers.Add(new User() { Username = "admin", Password = "admin" });
        }

        public User GetUser(string username)
        {
            try
            {
                return TestUsers.First(user => user.Username.Equals(username));
            }
            catch
            {
                return null;
            }
        }

    }
}
