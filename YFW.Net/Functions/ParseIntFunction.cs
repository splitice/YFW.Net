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

        public Delegate GetDelegate()
        {
            return new Func<object, int>((o) => int.Parse(o.ToString()));
        }
    }
}
