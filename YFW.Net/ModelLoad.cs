using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
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

        private DnsClient _dns = DnsClient.Default;

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
            if (rule.Contains("{"))
            {
                foreach (var v in c.Versions)
                {
                    var rules = _ruleSets[v];

                    foreach (var t in c.Tables)
                    {
                        IpTablesRule.ChainCreateMode chainMode = IpTablesRule.ChainCreateMode.DontCreateErrorInstead;
                        rule = c.Rule;
                        string formattedRule;
                        lock (_dynamicLock)
                        {
                            formattedRule = rb.Format(rule, t, v);
                        }
                        if (formattedRule != rule)
                        {
                            rule = formattedRule;
                            chainMode = IpTablesRule.ChainCreateMode.ReturnNewChain;
                        }

                        yield return IpTablesRule.Parse(rule, _iptables, rules.Chains, v, t, chainMode);
                    }
                }
            }
            else
            {
                IpTablesRule ruleTemplate = null;

                foreach (var v in c.Versions)
                {
                    var chains = _ruleSets[v].Chains;
                    foreach (var t in c.Tables)
                    {
                        if (ruleTemplate == null)
                        {
                            ruleTemplate = IpTablesRule.Parse(rule, _iptables, chains, v, t,
                                IpTablesRule.ChainCreateMode.DontCreateErrorInstead);
                            yield return ruleTemplate;
                        }
                        else
                        {
                            //TODO: IPTables Rule clone
                            var theRule = new IpTablesRule(ruleTemplate);
                            theRule.Chain = chains.GetChainOrDefault(ruleTemplate.Chain.Name, t);
                            yield return theRule;
                        }
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
                        continue;
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


        private Action<Task<DnsMessage>> CompleteLambda(int index, string[] resolved)
        {
            return (task) =>
            {
                var result = task.Result;
                var ips = result.AnswerRecords;
                if (ips.Any((a)=>a is ARecord))
                {
                    String entryIp2 = (ips.First(a => a is ARecord) as ARecord).Address.ToString();
                    resolved[index] = entryIp2;
                }
            };
        }

        private void CreateSets(IpTablesDetails config, RuleBuilder rb)
        {
            foreach (var set in config.Sets)
            {
                var ipset = new IpSetSet(IpSetTypeHelper.StringToType(set.Type), set.Name, 0, set.Family, _iptables, IpSetSyncMode.SetAndEntries);
                String[] resolved = set.Entries.ToArray();

                if (ipset.Type == IpSetType.HashIp)
                {
                    IPAddress ip;
                    int retries = 0;
                    do
                    {
                        List<Task> tasks = new List<Task>();
                        for (int index = 0; index < resolved.Length; index++)
                        {
                            var entry = resolved[index];

                            String entryIp = rb.Format(entry);
                            if (!IPAddress.TryParse(entryIp, out ip))
                            {
                                var asyncResult = _dns.ResolveAsync(DomainName.Parse(entryIp)).ContinueWith(CompleteLambda(index, resolved));
                                tasks.Add(asyncResult);
                            }
                        }

                        if (tasks.Any())
                        {
                            Task.WaitAll(tasks.ToArray());
                        }
                    } while (++retries <= 3 && resolved.Any((entry) => !IPAddress.TryParse(rb.Format(entry), out ip)));
                    for (int index = 0; index < resolved.Length; index++)
                    {
                        var entry = resolved[index];

                        String entryIp = rb.Format(entry);
                        if (!IPAddress.TryParse(entryIp, out ip))
                        {
                            throw new Exception("Unable to resolve "+entryIp);
                        }
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
