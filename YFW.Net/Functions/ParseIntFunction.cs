using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace YFW.Net.Functions
{
    class ParseIntFunction : IFwFunction
    {
        public string Name
        {
            get { return "ParseInt"; }
        }
        public dynamic Process(object o)
        {
            return int.Parse(o.ToString());
        }
    }
}
