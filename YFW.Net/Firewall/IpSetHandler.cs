using System;
using System.Collections.Generic;
using System.Net;

namespace YFW.Net.Firewall
{
    public class IpSetHandler
    {
        public List<IPAddress> GetEntries(String handler)
        {
            var meth = GetType().GetMethod(handler);
            return (List<IPAddress>)meth.Invoke(this, new object[0]); // assuming a no-arg method
        }
    }
}
