using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DynamicExpresso;
using YFW.Net.Functions;

namespace YFW.Net
{
    public class FunctionRegistry
    {
        private List<IFwFunction> _functions = new List<IFwFunction>();

        public FunctionRegistry(bool standardFunctions = true)
        {
            if (standardFunctions)
            {
                RegisterFunction(new ParseIntFunction());
                RegisterFunction(new CheckFunction());
            }
        }

        public void RegisterFunction(IFwFunction function)
        {
            _functions.Add(function);
        }

        internal void LoadFunctions(Interpreter interpreter)
        {
            foreach (var func in _functions)
            {
                interpreter.SetFunction(func.Name, func.GetDelegate());
            }
        }
    }
}
