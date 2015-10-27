using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Dynamic;
using System.Linq;
using SystemInteract;
using DynamicExpresso;
using IPTables.Net;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Helpers;
using YFW.Net.Firewall;
using YFW.Net.Firewall.Dicts;
using YFW.Net.StringFormatter;

namespace YFW.Net
{
    public class RuleBuilder
    {
        private Dictionary<String, object> _mappings = new Dictionary<string, object>();
        private HashSet<IpTablesChain> _dynamicChainsCreated = new HashSet<IpTablesChain>(); 
        private DynamicObject _formatDb;
        private ISystemFactory _system;
        private string _nfbpf;
        private DynamicChainRegister _dcr;
        private Dictionary<int, IpTablesRuleSet> _ruleSets; 
        private string _tableState;
        private int _versionState;
        private Interpreter _interpreter;

        public RuleBuilder(IpTablesSystem system, String nfbpf, Dictionary<int, IpTablesRuleSet> ruleSets, FunctionRegistry functions = null)
        {
            if (functions == null)
            {
                functions = new FunctionRegistry();
            }
            _system = system.System;
            _nfbpf = nfbpf;
            var chainsDict =
                ruleSets.Select((a) => new KeyValuePair<int, IpTablesChainSet>(a.Key, a.Value.Chains))
                    .ToDictionary((a) => a.Key, (a) => a.Value);
            _dcr = new DynamicChainRegister(system, chainsDict);
            _formatDb = new DynamicDictionary<object>(_mappings);
            _ruleSets = ruleSets;
            _interpreter = new Interpreter();
            _interpreter.SetVariable("var", _mappings);
            functions.LoadFunctions(_interpreter);
        }

        public DynamicChainRegister Dcr
        {
            get { return _dcr; }
        }

        private string DynamicLookup(string dynamicName, string subname)
        {
            if (_tableState == null)
            {
                return null;
            }

            var chain = Dcr.GetByVariable(dynamicName, _tableState, _versionState);
            if (chain == null)
            {
                throw new Exception("Variable " + dynamicName + " not found");
            }
            Debug.Assert(Dcr.IsDynamic(chain));
            var chainName = String.Format(chain.Name, subname);

            var createdChain = new IpTablesChain(chain.Table, chainName, chain.IpVersion, null);

            if (_dynamicChainsCreated.Contains(createdChain))
            {
                return chainName;
            }

            var ruleset = _ruleSets[chain.IpVersion];

            //Get chain rules, for all applicable tables and versions
            var rules = Dcr.GetDynamicChainRules(chain, subname);
            foreach (var r in rules)
            {
                ruleset.AddRule(r);
            }
            _dynamicChainsCreated.Add(createdChain);

            return chainName;
        }

        public String Format(String template, String table = null, int version = 4)
        {
            _tableState = table;
            _versionState = version;
            try
            {
                return HaackFormatter.HaackFormat(template, _formatDb);
            }
            catch (FormatException ex)
            {
                throw new FormatException(ex.Message + " Template: \"" + template + "\".", ex);
            }
        }

        public String ExecuteBash(String code)
        {
            String error;
            return ExecuteBash(code, out error);
        }

        public String ExecuteBash(String code, out String error)
        {
            var process = _system.StartProcess("bash", "-");
            process.StandardInput.WriteLine(code);
            process.StandardInput.Close();
            process.WaitForExit();
            var output = process.StandardOutput.ReadToEnd();
            error = process.StandardError.ReadToEnd().TrimEnd(new char[]{'\n'});

            return output.TrimEnd(new char[]{'\n'});
        }

        public string DefineByBash(String name, String code, String def = "")
        {
            String result = ExecuteBash(code);
            _mappings.Add(name, result);
            if (String.IsNullOrEmpty(result.Trim()))
            {
                _mappings[name] = def;
                result = def;
            }
            return result;
        }

        public void DefineByBpf(string key, string command)
        {
            String result = CompileBpf(command);
            _mappings.Add(key, result);
        }

        public void DefineByText(string key, string value)
        {
            _mappings.Add(key, value);
        }

        public string CompileBpf(string command)
        {
            String error;
            return CompileBpf(command, out error);
        }

        public string CompileBpf(string command, out String error)
        {
            return ExecuteBash(_nfbpf + " RAW " + ShellHelper.EscapeArguments(command), out error);
        }

        public void DefineDynamicChain(string name)
        {
            _mappings.Add(name, new DynamicDictionaryCallback((a)=>DynamicLookup(name,a)));
        }

        public bool IsConditionTrue(String condition)
        {
            if (String.IsNullOrWhiteSpace(condition))
            {
                return true;
            }
            return _interpreter.Eval<bool>(condition);
        }
    }
}
