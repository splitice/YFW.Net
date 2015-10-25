using System.Collections.Generic;
using System.Dynamic;

namespace YFW.Net.Firewall.Dicts
{
    public class DynamicDictionaryMerge : DynamicObject
    {
        private IEnumerable<DynamicObject> _dicts;

        public DynamicDictionaryMerge(IEnumerable<DynamicObject> dicts)
        {
            _dicts = dicts;
        }

        public override bool TryGetMember(
            GetMemberBinder binder, out object result)
        {
            foreach (var d in _dicts)
            {
                bool ret = d.TryGetMember(binder, out result);
                if (ret)
                {
                    return true;
                }
            }
            result = null;
            return false;
        }

        public override bool TrySetMember(
            SetMemberBinder binder, object value)
        {
            return true;
        }
    }
}
