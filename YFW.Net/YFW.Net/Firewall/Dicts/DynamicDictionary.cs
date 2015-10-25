using System;
using System.Collections.Generic;
using System.Dynamic;

namespace YFW.Net.Firewall.Dicts
{
    public class DynamicDictionary<T> : DynamicObject
    {
        private readonly Dictionary<string, T> dictionary;

        public Dictionary<String, T> Dictionary
        {
            get { return dictionary; }
        } 

        public DynamicDictionary(Dictionary<string, T> dictionary)
        {
            this.dictionary = dictionary;
        }

        public override bool TryGetMember(
            GetMemberBinder binder, out object result)
        {
            T oresult;
            bool r = dictionary.TryGetValue(binder.Name, out oresult);
            result = oresult;
            return r;
        }

        public override bool TrySetMember(
            SetMemberBinder binder, object value)
        {
            dictionary[binder.Name] = (T)value;

            return true;
        }
    }
}
