using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace YFW.Net.Functions
{
    public interface IFwFunction
    {
        String Name { get; }
        dynamic Process(object o);
    }
}
