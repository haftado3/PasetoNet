using System;

namespace PasetoAuth4.Exceptions
{
    public class InvalidGrantType : Exception
    {
        public InvalidGrantType() : base("This grant type is unsupported")
        {
            
        }
    }
}