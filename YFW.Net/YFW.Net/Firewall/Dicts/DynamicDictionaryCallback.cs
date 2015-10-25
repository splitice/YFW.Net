using System;
using System.Dynamic;

namespace YFW.Net.Firewall.Dicts
{
    public class DynamicDictionaryCallback : DynamicObject
    {
        private Func<string, string> _cb;

        public DynamicDictionaryCallback(Func<String, String> cb)
        {
            _cb = cb;
        }

        public override bool TryGetMember(
            GetMemberBinder binder, out object result)
        {
            var r = _cb(binder.Name);
            if (String.IsNullOrEmpty(r))
            {
                result = null;
                return false;
            }
            result = r;
            return true;
        }

        public override bool TrySetMember(
            SetMemberBinder binder, object value)
        {
            return true;
        }
    }
}
