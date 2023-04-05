using System;

namespace PasetoAuth4.Exceptions
{
    public class ExpiredToken : Exception
    {
        public ExpiredToken(string message = "Token expired.") : base(message)
        {
            
        }
    }
}