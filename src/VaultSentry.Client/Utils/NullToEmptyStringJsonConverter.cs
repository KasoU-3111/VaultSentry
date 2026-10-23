using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VaultSentry.Client.Utils
{
    /// <summary>
    /// Converts incoming null JSON tokens into empty strings during deserialization
    /// to eliminate 'Value must be set' exceptions in WPF bindings.
    /// </summary>
    public class NullToEmptyStringJsonConverter : JsonConverter<string>
    {
        public override string Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.Null)
            {
                return string.Empty;
            }

            return reader.GetString() ?? string.Empty;
        }

        public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value ?? string.Empty);
        }
    }
}