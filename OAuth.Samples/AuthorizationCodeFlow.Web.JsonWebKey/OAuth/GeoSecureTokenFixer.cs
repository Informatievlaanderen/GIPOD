using System;
using System.IO;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AuthorizationCodeFlow.Web.JsonWebKey.OAuth
{
    public static class GeoSecureTokenFixer
    {
        public static string Fixit(string token)
        {
            //make geosecure great again
            var strArray = token.Split('.');
            var jsonPayLoad =  Encoding.UTF8.GetString(CustomFromBase64(strArray[1]));

            if (IsJsonTokenValid(jsonPayLoad))
            {
                return strArray.Length == 3 ? token : $"{token}.";
            }

            var validJson = DeserializeAndCombineDuplicates(new JsonTextReader(new StringReader(jsonPayLoad)));
            return $"{strArray[0]}.{Convert.ToBase64String(Encoding.UTF8.GetBytes(validJson.ToString()))}.";
        }

        private static JToken DeserializeAndCombineDuplicates(JsonTextReader reader)
        {
            if (reader.TokenType == JsonToken.None)
            {
                reader.Read();
            }

            if (reader.TokenType == JsonToken.StartObject)
            {
                reader.Read();
                JObject obj = new JObject();
                while (reader.TokenType != JsonToken.EndObject)
                {
                    string propName = (string)reader.Value;
                    reader.Read();
                    JToken newValue = DeserializeAndCombineDuplicates(reader);

                    JToken existingValue = obj[propName];
                    if (existingValue == null)
                    {
                        obj.Add(new JProperty(propName, newValue));
                    }
                    else if (existingValue.Type == JTokenType.Array)
                    {
                        CombineWithArray((JArray)existingValue, newValue);
                    }
                    else // Convert existing non-array property value to an array
                    {
                        JProperty prop = (JProperty)existingValue.Parent;
                        JArray array = new JArray();
                        prop.Value = array;
                        array.Add(existingValue);
                        CombineWithArray(array, newValue);
                    }

                    reader.Read();
                }
                return obj;
            }

            if (reader.TokenType == JsonToken.StartArray)
            {
                reader.Read();
                JArray array = new JArray();
                while (reader.TokenType != JsonToken.EndArray)
                {
                    array.Add(DeserializeAndCombineDuplicates(reader));
                    reader.Read();
                }
                return array;
            }

            return new JValue(reader.Value);
        }

        private static void CombineWithArray(JArray array, JToken value)
        {
            if (value.Type == JTokenType.Array)
            {
                foreach (JToken child in value.Children())
                    array.Add(child);
            }
            else
            {
                array.Add(value);
            }
        }

        private static byte[] CustomFromBase64(string base64String)
        {
            base64String = base64String.Replace('-', '+').Replace('_', '/');
            switch (base64String.Length % 4)
            {
                case 2:
                    return Convert.FromBase64String($"{base64String}==");
                case 3:
                    return Convert.FromBase64String($"{base64String}=");
                default:
                    return Convert.FromBase64String(base64String);
            }
        }

        private static bool IsJsonTokenValid(string json)
        {
            try
            {
                JToken.Parse(json,  new JsonLoadSettings { DuplicatePropertyNameHandling = DuplicatePropertyNameHandling.Error });
                return true;
            }
            catch (JsonReaderException)
            {
                return false;
            }
        }
    }
}