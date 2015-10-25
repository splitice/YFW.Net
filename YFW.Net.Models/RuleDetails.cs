using System;
using System.Collections.Generic;
using System.Linq;
using YamlDotNet.Serialization;

namespace YFW.Net.Models
{
    public class RuleDetails
    {
        private static Dictionary<String, int> RuleMap = new Dictionary<string, int>{{"ipv4",4},{"ipv6",6}}; 
        private String _rule;
        private List<string> _tables = new List<string>(); 
        private List<int> _versions = new List<int>{4};
        private String _condition;

        public List<int> Versions
        {
            get { return _versions; }
        }

        [YamlMember(Alias="protocol")]
        public List<string> VersionsConfig
        {
            get { return _versions.Select((a) => "ipv" + a).ToList(); }
            set { _versions = value.Select((a) => RuleMap[a]).ToList(); }
        }

        [YamlMember(Alias = "rule")]
        public string Rule
        {
            get { return _rule; }
            set { _rule = value; }
        }

        [YamlMember(Alias="table")]
        public List<string> Tables
        {
            get { return _tables; }
            set { _tables = value; }
        }

        [YamlMember(Alias = "condition")]
        public string Condition
        {
            get { return _condition; }
            set { _condition = value; }
        }

        public RuleDetails()
        {
            
        }

        public RuleDetails(String rule, List<int> versions)
        {
            _rule = rule;
            _versions = versions;
        }
    }
}
