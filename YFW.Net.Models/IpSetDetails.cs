using System;
using System.Collections.Generic;
using YamlDotNet.Serialization;

namespace YFW.Net.Models
{
    public class IpSetDetails
    {
        private String _name;
        private List<String> _entries;
        private String _handler;
        private String _type;
        private String _family = "inet";

        [YamlMember(Alias = "handler")]
        public string Handler
        {
            get { return _handler; }
            set { _handler = value; }
        }

        [YamlMember(Alias = "entries")]
        public List<String> Entries
        {
            get { return _entries; }
            set { _entries = value; }
        }

        [YamlMember(Alias = "name")]
        public string Name
        {
            get { return _name; }
            set { _name = value; }
        }

        [YamlMember(Alias="type")]
        public string Type
        {
            get { return _type; }
            set { _type = value; }
        }

        [YamlMember(Alias = "family")]
        public string Family
        {
            get { return _family; }
            set { _family = value; }
        }
    }
}
