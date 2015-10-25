using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace YFW.Net.Functions
{
    class CheckFunction : IFwFunction
    {
        public string Name
        {
            get { return "Check"; }
        }
        public dynamic Process(object o)
        {
            if (o == null)
            {
                return false;
            }
            return o.ToString().Trim(new char[] { '0' }).Length == 0;
        }
    }
}
