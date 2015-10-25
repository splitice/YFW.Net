﻿using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Dynamic;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Web;
using System.Web.UI;
using Microsoft.CSharp.RuntimeBinder;

namespace YFW.Net.StringFormatter
{
    public sealed class DataBinder
    {
        public DataBinder()
        {
        }

        internal static string FormatResult(object result, string format)
        {
            if (result == null)
                return String.Empty;

            if (format == null || format.Length == 0)
                return result.ToString();

            return String.Format(format, result);
        }

        public static object Eval(object container, string expression)
        {
            expression = expression != null ? expression.Trim() : null;
            if (expression == null || expression.Length == 0)
                throw new ArgumentNullException("expression");

            object current = container;
            while (current != null)
            {
                int dot = expression.IndexOf('.');
                int size = (dot == -1) ? expression.Length : dot;
                string prop = expression.Substring(0, size);

                if (prop.IndexOf('[') != -1)
                    current = GetIndexedPropertyValue(current, prop);
                else
                    current = GetPropertyValue(current, prop);

                if (dot == -1)
                    break;

                expression = expression.Substring(prop.Length + 1);
            }

            return current;
        }

        public static string Eval(object container, string expression, string format)
        {
            object result = Eval(container, expression);
            return FormatResult(result, format);
        }

        public static object GetIndexedPropertyValue(object container, string expr)
        {
            if (container == null)
                throw new ArgumentNullException("container");
            if ((expr == null) || (expr.Length == 0))
                throw new ArgumentNullException("expr");

            int openIdx = expr.IndexOf('[');
            int closeIdx = expr.IndexOf(']'); // see the test case. MS ignores all after the first ]
            if (openIdx < 0 || closeIdx < 0 || closeIdx - openIdx <= 1)
                throw new ArgumentException(expr + " is not a valid indexed expression.");

            string val = expr.Substring(openIdx + 1, closeIdx - openIdx - 1);
            val = val.Trim();
            if (val.Length == 0)
                throw new ArgumentException(expr + " is not a valid indexed expression.");

            bool is_string = false;
            // a quoted val means we have a string
            if ((val[0] == '\'' && val[val.Length - 1] == '\'') ||
                (val[0] == '\"' && val[val.Length - 1] == '\"'))
            {
                is_string = true;
                val = val.Substring(1, val.Length - 2);
            }
            else
            {
                // if all chars are digits, then we have a int
                for (int i = 0; i < val.Length; i++)
                    if (!Char.IsDigit(val[i]))
                    {
                        is_string = true;
                        break;
                    }
            }

            int intVal = 0;
            if (!is_string)
            {
                try
                {
                    intVal = Int32.Parse(val);
                }
                catch
                {
                    throw new ArgumentException(expr + " is not a valid indexed expression.");
                }
            }

            string property = null;
            if (openIdx > 0)
            {
                property = expr.Substring(0, openIdx);
                if (property != null && property.Length > 0)
                    container = GetPropertyValue(container, property);
            }

            if (container == null)
                return null;

            if (container is System.Collections.IList)
            {
                if (is_string)
                    throw new ArgumentException(expr + " cannot be indexed with a string.");
                IList l = (IList)container;
                return l[intVal];
            }

            Type t = container.GetType();

            // MS does not seem to look for any other than "Item"!!!
            object[] atts = t.GetCustomAttributes(typeof(DefaultMemberAttribute), false);
            if (atts.Length != 1)
                property = "Item";
            else
                property = ((DefaultMemberAttribute)atts[0]).MemberName;

            Type[] argTypes = new Type[] { (is_string) ? typeof(string) : typeof(int) };
            PropertyInfo prop = t.GetProperty(property, argTypes);
            if (prop == null)
                throw new ArgumentException(expr + " indexer not found.");

            object[] args = new object[1];
            if (is_string)
                args[0] = val;
            else
                args[0] = intVal;

            return prop.GetValue(container, args);
        }

        public static string GetIndexedPropertyValue(object container, string expr, string format)
        {
            object result = GetIndexedPropertyValue(container, expr);
            return FormatResult(result, format);
        }

        public static object GetPropertyValue(object container, string propName)
        {
            if (container == null)
                throw new ArgumentNullException("container");
            if (propName == null || propName.Length == 0)
                throw new ArgumentNullException("propName");

            if (container is DynamicObject)
            {
                try
                {
                    var binder = Microsoft.CSharp.RuntimeBinder.Binder.GetMember(CSharpBinderFlags.None, propName,
                        container.GetType(),
                        new[] {CSharpArgumentInfo.Create(CSharpArgumentInfoFlags.None, null)});
                    var callsite = CallSite<Func<CallSite, object, object>>.Create(binder);
                    return callsite.Target(callsite, container);
                }
                catch (Exception)
                {
                    
                }
            }

            PropertyDescriptor prop = TypeDescriptor.GetProperties(container).Find(propName, true);
            if (prop == null)
            {
                throw new HttpException("Property " + propName + " not found in " +
                             container.GetType());
            }

            return prop.GetValue(container);
        }

        public static string GetPropertyValue(object container, string propName, string format)
        {
            object result = GetPropertyValue(container, propName);
            return FormatResult(result, format);
        }

        [ThreadStatic]
        static Dictionary<Type, PropertyInfo> dataItemCache;

        public static object GetDataItem(object container, out bool foundDataItem)
        {
            foundDataItem = false;
            if (container == null)
                return null;

            if (container is IDataItemContainer)
            {
                foundDataItem = true;
                return ((IDataItemContainer)container).DataItem;
            }

            PropertyInfo pi = null;
            if (dataItemCache == null)
                dataItemCache = new Dictionary<Type, PropertyInfo>();

            Type type = container.GetType();
            if (!dataItemCache.TryGetValue(type, out pi))
            {
                pi = type.GetProperty("DataItem", BindingFlags.Public | BindingFlags.Instance);
                dataItemCache[type] = pi;
            }

            if (pi == null)
                return null;

            foundDataItem = true;

            return pi.GetValue(container, null);
        }


        public static object GetDataItem(object container)
        {
            bool flag;
            return GetDataItem(container, out flag);
        }
    }
}