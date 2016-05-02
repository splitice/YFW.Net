using System;
using System.IO;
using System.Web;

namespace YFW.Net.StringFormatter
{
public class FormatExpression : ITextExpression
{
  bool _invalidExpression = false;

  public FormatExpression(string expression) {
    if (!expression.StartsWith("{") || !expression.EndsWith("}")) {
      _invalidExpression = true;
      Expression = expression;
      return;
    }

    string expressionWithoutBraces = expression.Substring(1
        , expression.Length - 2);
    int colonIndex = expressionWithoutBraces.IndexOf(':');
    if (colonIndex < 0) {
      Expression = expressionWithoutBraces;
    }
    else {
      Expression = expressionWithoutBraces.Substring(0, colonIndex);
      Format = expressionWithoutBraces.Substring(colonIndex + 1);
    }
  }

  public string Expression { 
    get; 
    private set; 
  }

  public string Format
  {
    get;
    private set;
  }

  public string Eval(object o) {
    if (_invalidExpression) {
      throw new FormatException("Invalid expression");
    }
    try
    {
      if (System.String.IsNullOrEmpty(Format))
      {
        return (DataBinder.Eval(o, Expression) 
            ?? string.Empty).ToString();
      }
      return (DataBinder.Eval(o, Expression, "{0:" + Format + "}") 
          ?? string.Empty).ToString();
    }
    catch (InvalidDataException ex)
    {
      throw new FormatException("Invalid Format", ex);
    }
  }
}
}
