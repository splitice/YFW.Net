using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IPTables.Net;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.IpSet;
using YFW.Net.Firewall;
using YFW.Net.Models;

namespace YFW.Net
{
    public class ModelLoad
    {
        private IpTablesSystem _iptables;
        private Dictionary<int, IpTablesRuleSet> _ruleSets;
        private IpSetSets _sets;

        public ModelLoad(IpTablesSystem iptables, Dictionary<int, IpTablesRuleSet> ruleSets, IpSetSets sets)
        {
            _iptables = iptables;
            _ruleSets = ruleSets;
            _sets = sets;
        }

        private RuleBuilder InitEnvironment(Dictionary<String, EnvironmentDetails> environment)
        {
            RuleBuilder rb = new RuleBuilder(_iptables, "/var/x4b/bin/bpf/nfbpf_compile", _ruleSets);
            foreach (var e in environment)
            {
                if (e.Value.Language == "bash")
                {
                    rb.DefineByBash(e.Key, e.Value.Command, e.Value.Default);
                }
                else if (e.Value.Language == "bpf")
                {
                    rb.DefineByBpf(e.Key, e.Value.Command);
                }
                else if (e.Value.Language == "text")
                {
                    rb.DefineByText(e.Key, e.Value.Command);
                }
                else
                {
                    throw new Exception("Invalid language: " + e.Value.Language);
                }
            }
            return rb;
        }

        private void CreateChains(IpTablesDetails config, RuleBuilder rb)
        {
            foreach (var c in config.Chains)
            {
                if (c.IsDynamic)
                {
                    rb.DefineDynamicChain(c.Dynamic);
                }
                foreach (var v in c.Versions)
                {
                    var rules = _ruleSets[v];
                    foreach (var t in c.Tables)
                    {
                        if (c.IsDynamic)
                        {
                            rb.Dcr.RegisterDynamicChain(c.Dynamic, t, c.Name, v);
                        }
                        else if (!rules.Chains.HasChain(c.Name, t))
                        {
                            rules.AddChain(c.Name, t);
                        }
                    }
                }
            }
        }

        private void CreateRules(IpTablesDetails config, RuleBuilder rb)
        {
            foreach (var c in config.Rules)
            {
                if (rb.IsConditionTrue(c.Condition))
                {
                    foreach (var v in c.Versions)
                    {
                        var rules = _ruleSets[v];
                        foreach (var t in c.Tables)
                        {
                            var rule = IpTablesRule.Parse(rb.Format(c.Rule, t, v), _iptables, rules.Chains,
                                v, t, IpTablesRule.ChainCreateMode.ReturnNewChain);
                            if (rb.Dcr.IsDynamic(rule.Chain))
                            {
                                rb.Dcr.AddRule(rule);
                            }
                            else
                            {
                                if (!rules.Chains.HasChain(rule.Chain.Name, rule.Chain.Table))
                                {
                                    throw new Exception(String.Format("Chain was not created ipv{0},{1}:{2}",
                                        rule.Chain.IpVersion, rule.Chain.Table, rule.Chain.Name));
                                }
                                rules.AddRule(rule);
                            }
                        }
                    }
                }
            }
        }

        private void CreateSets(IpTablesDetails config, RuleBuilder rb)
        {
            foreach (var set in config.Sets)
            {
                var ipset = new IpSetSet(IpSetTypeHelper.StringToType(set.Type), set.Name, 0, _iptables, IpSetSyncMode.SetAndEntries);
                foreach (var entry in set.Entries)
                {
                    ipset.Entries.Add(IpSetEntry.ParseFromParts(ipset, rb.Format(entry)));
                }
                _sets.AddSet(ipset);
            }

            //Add new sets (dont delete!)
            _sets.Sync((a) => false);
        }

        public void InitFromModel(Dictionary<String, EnvironmentDetails> environment, IpTablesDetails config)
        {
            var rb = InitEnvironment(environment);
            CreateChains(config, rb);
            CreateSets(config, rb);
            CreateRules(config, rb);
        }
    }
}
