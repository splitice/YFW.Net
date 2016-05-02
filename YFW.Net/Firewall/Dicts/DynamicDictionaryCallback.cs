using System;
using System.Dynamic;

namespace YFW.Net.Firewall.Dicts
{
    public class DynamicDictionaryCallback<T> : DynamicObject
    {
        private Func<string, T> _cb;

        public DynamicDictionaryCallback(Func<String, T> cb)
        {
            _cb = cb;
        }

        public override bool TryGetMember(
            GetMemberBinder binder, out object result)
        {
            var r = _cb(binder.Name);
            if (r == null)
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

    public class DynamicDictionaryCallback : DynamicDictionaryCallback<string>
    {
        public DynamicDictionaryCallback(Func<string, string> cb) : base(cb)
        {
        }
    }
}
