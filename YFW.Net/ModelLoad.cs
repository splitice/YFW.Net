using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
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
            var mappings = environment.AsParallel().Select((e) =>
            {
                if (e.Value.Language == "bash")
                {
                    e.Value.Command = rb.ExecuteBash(e.Value.Command);
                }
                else if (e.Value.Language == "bpf")
                {
                    e.Value.Command = rb.CompileBpf("RAW", e.Value.Command);
                }
                else if (e.Value.Language == "bpfl4")
                {
                    e.Value.Command = rb.CompileBpf("RAW_TRANSPORT", e.Value.Command);
                }
                else if (e.Value.Language != "text")
                {
                    throw new Exception("Invalid language: " + e.Value.Language);
                }
                return e;
            });

            foreach (var e in mappings)
            {
                rb.DefineMapping(e.Key, e.Value.Command, e.Value.Default);
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
                    var chains = rules.Chains;
                    foreach (var t in c.Tables)
                    {
                        if (c.IsDynamic)
                        {
                            rb.Dcr.RegisterDynamicChain(c.Dynamic, t, c.Name, v);
                        }
                        else if (!chains.HasChain(c.Name, t))
                        {
                            chains.AddChain(c.Name, t, _iptables);
                        }
                    }
                }
            }
        }

        private object _dynamicLock = new object();
        private IEnumerable<IpTablesRule> ParseAll(RuleBuilder rb, RuleDetails c)
        {
            var rule = c.Rule;
            foreach (var v in c.Versions)
            {
                var rules = _ruleSets[v];
                foreach (var t in c.Tables)
                {
                    bool dynamic = false;
                    if (rule.Contains("{"))
                    {
                        string formattedRule;
                        lock(_dynamicLock)
                        {
                            formattedRule = rb.Format(rule, t, v);
                        }
                        if (formattedRule != rule)
                        {
                            rule = formattedRule;
                            dynamic = true;
                        }
                    }

                    if (dynamic)
                    {
                        yield return IpTablesRule.Parse(rule, _iptables, rules.Chains,
                            v, t, IpTablesRule.ChainCreateMode.ReturnNewChain);
                    }
                    else
                    {
                        yield return IpTablesRule.Parse(rule, _iptables, rules.Chains,
                            v, t, IpTablesRule.ChainCreateMode.DontCreateErrorInstead);
                    }
                }
            }
        } 

        private void CreateRules(IpTablesDetails config, RuleBuilder rb)
        {
            var rules = config.Rules.AsParallel().AsOrdered()
                .Where((c) => rb.IsConditionTrue(c.Condition))
                .SelectMany((c) => ParseAll(rb, c)).AsSequential();

            foreach(var rule in rules){
                lock (_dynamicLock)
                {
                    if (rb.Dcr.IsDynamic(rule.Chain))
                    {
                        rb.Dcr.AddRule(rule);
                        return;
                    }
                }

                var chains = _ruleSets[rule.IpVersion].Chains;
                IpTablesChain chain;
                lock (chains)
                {
                    chain = chains.GetChainOrDefault(rule.Chain.Name, rule.Chain.Table);
                }
                if (chain == null)
                {
                    throw new Exception(String.Format("Chain was not created ipv{0},{1}:{2}",
                        rule.Chain.IpVersion, rule.Chain.Table, rule.Chain.Name));
                }
                lock (chain)
                {
                    chain.AddRule(rule);
                }
            }
        }

        private void CreateSets(IpTablesDetails config, RuleBuilder rb)
        {
            foreach (var set in config.Sets)
            {
                var ipset = new IpSetSet(IpSetTypeHelper.StringToType(set.Type), set.Name, 0, set.Family, _iptables, IpSetSyncMode.SetAndEntries);
                String[] resolved = set.Entries.ToArray();

                if (ipset.Type == IpSetType.HashIp)
                {
                    List<IAsyncResult> tasks = new List<IAsyncResult>();
                    for (int index = 0; index < resolved.Length; index++)
                    {
                        var entry = resolved[index];

                        String entryIp = rb.Format(entry);
                        IPAddress ip;
                        if (!IPAddress.TryParse(entryIp, out ip))
                        {
                            var asyncResult = Dns.BeginGetHostAddresses(entryIp, (a) =>
                            {
                                var ips = Dns.EndGetHostAddresses(a);
                                if (ips.Length == 0)
                                {
                                    throw new Exception("Unable to resolve: " + entryIp);
                                }
                                String entryIp2 = ips.First().ToString();
                                resolved[(int) a.AsyncState] = entryIp2;
                            }, index);
                            tasks.Add(asyncResult);
                        }
                    }

                    if (tasks.Any()) { 
                        WaitHandle.WaitAll(tasks.Select((a) => a.AsyncWaitHandle).ToArray());
                    }
                }

                //Check Uniqueness
                HashSet<IpSetEntry> ipsetEntries = new HashSet<IpSetEntry>();

                for (int index = 0; index < resolved.Length; index++)
                {
                    var entry = resolved[index];
                    String entryIp = rb.Format(entry);
                    var setEntry = IpSetEntry.ParseFromParts(ipset, entryIp);
                    if (ipsetEntries.Add(setEntry))
                    {
                        ipset.Entries.Add(setEntry);
                    }
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
            foreach (var c in config.Chains)
            {
                if (c.IsDynamic)
                {
                    var chains = _ruleSets.Select(
                        (a) => a.Value.Chains.FirstOrDefault((d) => d.Name == c.Name && c.Tables.Contains(d.Table))).Where((a)=>a != null).ToList();
                    foreach (var di in c.DynamicInit)
                    {
                        foreach (var cc in chains)
                        {
                            rb.Dcr.GetDynamicChainRules(cc, di);
                        }
                    }
                }
            }
        }
    }
}
