using System;
using System.Collections.Generic;
using System.Diagnostics;
using IPTables.Net;
using IPTables.Net.Iptables;

namespace YFW.Net.Firewall
{
    public class DynamicChainRegister
    {
        private Dictionary<Tuple<String, String, int>, IpTablesChain> _variables = new Dictionary<Tuple<String, String, int>, IpTablesChain>();
        private Dictionary<IpTablesChain, List<IpTablesRule>> _dynamicChains = new Dictionary<IpTablesChain, List<IpTablesRule>>();
        private IpTablesSystem _system;
        private Dictionary<int,IpTablesChainSet> _chains;

        public DynamicChainRegister(IpTablesSystem system, Dictionary<int,IpTablesChainSet> chains)
        {
            _system = system;
            _chains = chains;
        }

        public void RegisterDynamicChain(String variable, String table, String chainName, int ipVersion)
        {
            var regChain = new IpTablesChain(table, chainName, ipVersion, _system);
            if (_dynamicChains.ContainsKey(regChain))
            {
                throw new Exception(String.Format("A chain of ipv{0},{1}:{2} is already registered", ipVersion, chainName, table));
            }
            _dynamicChains.Add(regChain, new List<IpTablesRule>());

            _variables.Add(new Tuple<string, string, int>(table, variable, ipVersion), regChain);//todo: Support for multiple table!
        }

        public IpTablesChain GetByVariable(String var, String table, int version)
        {
            var tup = new Tuple<string, string, int>(table, var, version);
            if (!_variables.ContainsKey(tup))
            {
                return null;
            }

            return _variables[tup];
        }

        public void AddRule(IpTablesRule rule)
        {
            Debug.Assert(IsDynamic(rule));
            _dynamicChains[rule.Chain].Add(rule);
        }

        public void FeedRule(IpTablesRule rule)
        {
            if (IsDynamic(rule))
            {
                AddRule(rule);
            }
        }

        public List<IpTablesRule> GetDynamicChainRules(IpTablesChain chain, String arg)
        {
            if (!IsDynamic(chain))
            {
                throw new Exception("Chain "+chain.Name+" should be dynamic");
            }

            var chains = _chains[chain.IpVersion];

            List<IpTablesRule> rules = new List<IpTablesRule>();
            var targetTemplate = _dynamicChains[chain];
            if (targetTemplate.Count == 0)
            {
                throw new Exception("Chain " + chain.Name + " should have rules");
            }
            foreach (var rule in targetTemplate)
            {
                var formatted = String.Format(rule.GetActionCommand(), arg);
                var newRule = IpTablesRule.Parse(formatted, _system, chains, rule.Chain.IpVersion,
                    rule.Chain.Table, IpTablesRule.ChainCreateMode.CreateNewChainIfNeeded);
                rules.Add(newRule);
            }
            return rules;
        }

        public bool IsDynamic(IpTablesChain chain)
        {
            var comparisonChain = new IpTablesChain(chain.Table, chain.Name, chain.IpVersion, _system);
            return _dynamicChains.ContainsKey(comparisonChain);
        }

        public bool IsDynamic(IpTablesRule rule)
        {
            return IsDynamic(rule.Chain);
        }
    }
}
