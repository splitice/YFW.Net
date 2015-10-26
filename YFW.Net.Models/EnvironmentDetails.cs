using System;
using YamlDotNet.Serialization;

namespace YFW.Net.Models
{
    public class EnvironmentDetails
    {
        private String _default = null;
        private String _command;
        private String _language = "bash";

        [YamlMember(Alias = "command")]
        public string Command
        {
            get { return _command; }
            set { _command = value; }
        }

        [YamlMember(Alias = "default")]
        public string Default
        {
            get { return _default; }
            set { _default = value; }
        }

        [YamlMember(Alias = "language")]
        public string Language
        {
            get { return _language; }
            set { _language = value; }
        }

        public EnvironmentDetails()
        {
            
        }
    }
}
