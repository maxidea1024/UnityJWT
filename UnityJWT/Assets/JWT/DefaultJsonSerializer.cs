using UnityEngine;

namespace JWT
{
    public class DefaultJsonSerializer : IJsonSerializer
    {
        public string Serialize(object obj)
        {
            return JsonUtility.ToJson(obj);
        }

        public T Deserialize<T>(string json)
        {
            return JsonUtility.FromJson<T>(json);
        }
    }
}
