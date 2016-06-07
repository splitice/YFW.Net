using System;
using System.Collections.Generic;
using System.Linq;
using YamlDotNet.Serialization;

namespace YFW.Net.Models
{
    public class ChainDetails
    {
        private static Dictionary<String, int> ChainMap = new Dictionary<string, int>{{"ipv4",4},{"ipv6",6}}; 
        private String _name;
        private List<string> _tables = new List<string>(); 
        private List<int> _versions = new List<int>{4};
        private String _dynamic = null;
        private List<String> _dynamicInit = new List<string>(); 

        public List<int> Versions
        {
            get { return _versions; }
        }

        [YamlMember(Alias = "protocol")]
        public List<string> VersionsConfig
        {
            get { return _versions.Select((a) => "ipv" + a).ToList(); }
            set
            {
                /*if (!String.IsNullOrEmpty(Dynamic) && value.Count > 1)
                {
                    throw new Exception("Dynamic chains can only be use with a single IPTables version");
                }*/
                _versions = value.Select((a) => ChainMap[a]).ToList();
            }
        }

        [YamlMember(Alias = "name")]
        public string Name
        {
            get { return _name; }
            set { _name = value; }
        }

        [YamlMember(Alias = "table")]
        public List<string> Tables
        {
            get { return _tables; }
            set { _tables = value; }
        }

        [YamlMember(Alias = "dynamic")]
        public String Dynamic
        {
            get { return _dynamic; }
            set
            {
                /*if (!String.IsNullOrEmpty(value) && _versions.Count > 1)
                {
                    throw new Exception("Dynamic chains can only be use with a single IPTables version");
                }*/
                _dynamic = value;
            }
        }

        public bool IsDynamic
        {
            get { return !String.IsNullOrEmpty(Dynamic); }
        }

        [YamlMember(Alias = "dynamic_init")]
        public List<string> DynamicInit
        {
            get { return _dynamicInit; }
            set { _dynamicInit = value; }
        }

        public ChainDetails()
        {
            
        }

        public ChainDetails(String name, List<int> versions)
        {
            _name = name;
            _versions = versions;
        }
    }
}
