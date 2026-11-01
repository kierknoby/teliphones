// Minimal, strict JSON for TELIPHONES contracts. Rejects duplicate keys, deep nesting and oversized input.
#pragma once

#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace tlp {

struct Error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

namespace json {

class Value {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };
    using Array = std::vector<Value>;
    using Object = std::map<std::string, Value>;

    Value() = default;
    Value(std::nullptr_t) {}
    Value(bool value) : type_(Type::Bool), bool_(value) {}
    Value(int value) : Value(static_cast<std::int64_t>(value)) {}
    Value(std::int64_t value) : type_(Type::Number), integer_(value), isInteger_(true) {}
    Value(const char* value) : type_(Type::String), string_(value) {}
    Value(std::string value) : type_(Type::String), string_(std::move(value)) {}
    Value(Array value) : type_(Type::Array), array_(std::move(value)) {}
    Value(Object value) : type_(Type::Object), object_(std::move(value)) {}
    static Value NonInteger() { Value v; v.type_ = Type::Number; return v; }

    Type type() const { return type_; }
    bool isNull() const { return type_ == Type::Null; }
    bool isBool() const { return type_ == Type::Bool; }
    bool isString() const { return type_ == Type::String; }
    bool isArray() const { return type_ == Type::Array; }
    bool isObject() const { return type_ == Type::Object; }
    bool isInteger() const { return type_ == Type::Number && isInteger_; }

    bool asBool() const;
    std::int64_t asInteger() const;
    const std::string& asString() const;
    const Array& asArray() const;
    const Object& asObject() const;

    bool has(const std::string& key) const;
    const Value& at(const std::string& key) const;

private:
    Type type_ = Type::Null;
    bool bool_ = false;
    std::int64_t integer_ = 0;
    bool isInteger_ = false;
    std::string string_;
    Array array_;
    Object object_;

    friend std::string Serialize(const Value& value);
};

// Integers are exact; fractional or exponent numbers parse as non-integer values that contracts reject.
Value Parse(const std::string& text, std::size_t maxBytes = 1024 * 1024);
// Compact output with sorted object keys.
std::string Serialize(const Value& value);

// Requires an object containing exactly the given keys.
void RequireExactKeys(const Value& value, const std::vector<std::string>& keys, const char* what);

}  // namespace json
}  // namespace tlp
