#include "Json.h"

#include <limits>
#include <set>

namespace tlp {
namespace json {

bool Value::asBool() const {
    if (type_ != Type::Bool) throw Error("Expected a JSON boolean.");
    return bool_;
}

std::int64_t Value::asInteger() const {
    if (!isInteger()) throw Error("Expected a JSON integer.");
    return integer_;
}

const std::string& Value::asString() const {
    if (type_ != Type::String) throw Error("Expected a JSON string.");
    return string_;
}

const Value::Array& Value::asArray() const {
    if (type_ != Type::Array) throw Error("Expected a JSON array.");
    return array_;
}

const Value::Object& Value::asObject() const {
    if (type_ != Type::Object) throw Error("Expected a JSON object.");
    return object_;
}

bool Value::has(const std::string& key) const {
    return type_ == Type::Object && object_.count(key) != 0;
}

const Value& Value::at(const std::string& key) const {
    const Object& object = asObject();
    auto found = object.find(key);
    if (found == object.end()) throw Error("Missing JSON field: " + key);
    return found->second;
}

namespace {

class Parser {
public:
    explicit Parser(const std::string& text) : text_(text) {}

    Value document() {
        Value value = parse(0);
        skipSpace();
        if (pos_ != text_.size()) fail("Unexpected trailing data");
        return value;
    }

private:
    const std::string& text_;
    std::size_t pos_ = 0;

    [[noreturn]] void fail(const char* message) const {
        throw Error(std::string("Invalid JSON: ") + message + " at offset " + std::to_string(pos_) + ".");
    }

    void skipSpace() {
        while (pos_ < text_.size() && (text_[pos_] == ' ' || text_[pos_] == '\t' || text_[pos_] == '\n' || text_[pos_] == '\r')) ++pos_;
    }

    bool consume(char expected) {
        skipSpace();
        if (pos_ < text_.size() && text_[pos_] == expected) {
            ++pos_;
            return true;
        }
        return false;
    }

    void literal(const char* word) {
        for (const char* p = word; *p; ++p, ++pos_) {
            if (pos_ >= text_.size() || text_[pos_] != *p) fail("Unknown literal");
        }
    }

    Value parse(int depth) {
        if (depth > 32) fail("Nesting too deep");
        skipSpace();
        if (pos_ >= text_.size()) fail("Unexpected end");
        char c = text_[pos_];
        if (c == '{') return object(depth);
        if (c == '[') return array(depth);
        if (c == '"') return Value(string());
        if (c == 't') { literal("true"); return Value(true); }
        if (c == 'f') { literal("false"); return Value(false); }
        if (c == 'n') { literal("null"); return Value(nullptr); }
        if (c == '-' || (c >= '0' && c <= '9')) return number();
        fail("Unexpected character");
    }

    Value object(int depth) {
        ++pos_;
        Value::Object result;
        if (consume('}')) return Value(std::move(result));
        do {
            skipSpace();
            if (pos_ >= text_.size() || text_[pos_] != '"') fail("Expected object key");
            std::string key = string();
            if (!consume(':')) fail("Expected ':'");
            Value item = parse(depth + 1);
            if (!result.emplace(std::move(key), std::move(item)).second) fail("Duplicate object key");
        } while (consume(','));
        if (!consume('}')) fail("Expected '}'");
        return Value(std::move(result));
    }

    Value array(int depth) {
        ++pos_;
        Value::Array result;
        if (consume(']')) return Value(std::move(result));
        do {
            result.push_back(parse(depth + 1));
            if (result.size() > 10000) fail("Array too large");
        } while (consume(','));
        if (!consume(']')) fail("Expected ']'");
        return Value(std::move(result));
    }

    static void appendUtf8(std::string& out, std::uint32_t cp) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }

    std::uint32_t hex4() {
        if (pos_ + 4 > text_.size()) fail("Truncated escape");
        std::uint32_t value = 0;
        for (int i = 0; i < 4; ++i) {
            char c = text_[pos_++];
            value <<= 4;
            if (c >= '0' && c <= '9') value |= static_cast<std::uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') value |= static_cast<std::uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') value |= static_cast<std::uint32_t>(c - 'A' + 10);
            else fail("Invalid escape");
        }
        return value;
    }

    std::string string() {
        ++pos_;
        std::string out;
        while (true) {
            if (pos_ >= text_.size()) fail("Unterminated string");
            unsigned char c = static_cast<unsigned char>(text_[pos_++]);
            if (c == '"') return out;
            if (c < 0x20) fail("Control character in string");
            if (c != '\\') {
                out += static_cast<char>(c);
                continue;
            }
            if (pos_ >= text_.size()) fail("Truncated escape");
            char e = text_[pos_++];
            switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    std::uint32_t cp = hex4();
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        if (pos_ + 2 > text_.size() || text_[pos_] != '\\' || text_[pos_ + 1] != 'u') fail("Unpaired surrogate");
                        pos_ += 2;
                        std::uint32_t low = hex4();
                        if (low < 0xDC00 || low > 0xDFFF) fail("Unpaired surrogate");
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        fail("Unpaired surrogate");
                    }
                    appendUtf8(out, cp);
                    break;
                }
                default: fail("Invalid escape");
            }
        }
    }

    Value number() {
        std::size_t start = pos_;
        bool negative = false;
        if (text_[pos_] == '-') { negative = true; ++pos_; }
        if (pos_ >= text_.size() || text_[pos_] < '0' || text_[pos_] > '9') fail("Invalid number");
        if (text_[pos_] == '0' && pos_ + 1 < text_.size() && text_[pos_ + 1] >= '0' && text_[pos_ + 1] <= '9') fail("Leading zero");
        std::uint64_t magnitude = 0;
        bool overflow = false;
        while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
            unsigned digit = static_cast<unsigned>(text_[pos_++] - '0');
            if (magnitude > (static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) - digit) / 10) overflow = true;
            else magnitude = magnitude * 10 + digit;
        }
        bool integral = true;
        if (pos_ < text_.size() && text_[pos_] == '.') {
            integral = false;
            ++pos_;
            if (pos_ >= text_.size() || text_[pos_] < '0' || text_[pos_] > '9') fail("Invalid fraction");
            while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') ++pos_;
        }
        if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
            integral = false;
            ++pos_;
            if (pos_ < text_.size() && (text_[pos_] == '+' || text_[pos_] == '-')) ++pos_;
            if (pos_ >= text_.size() || text_[pos_] < '0' || text_[pos_] > '9') fail("Invalid exponent");
            while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') ++pos_;
        }
        if (pos_ - start > 64) fail("Number too long");
        if (!integral || overflow) return Value::NonInteger();
        std::int64_t value = static_cast<std::int64_t>(magnitude);
        return Value(negative ? -value : value);
    }
};

void escape(std::string& out, const std::string& text) {
    static const char* hex = "0123456789abcdef";
    out += '"';
    for (unsigned char c : text) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out += hex[c >> 4];
                    out += hex[c & 15];
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    out += '"';
}

void write(std::string& out, const Value& value) {
    switch (value.type()) {
        case Value::Type::Null: out += "null"; break;
        case Value::Type::Bool: out += value.asBool() ? "true" : "false"; break;
        case Value::Type::Number:
            if (!value.isInteger()) throw Error("Only integer JSON numbers can be written.");
            out += std::to_string(value.asInteger());
            break;
        case Value::Type::String: escape(out, value.asString()); break;
        case Value::Type::Array: {
            out += '[';
            bool first = true;
            for (const Value& item : value.asArray()) {
                if (!first) out += ',';
                first = false;
                write(out, item);
            }
            out += ']';
            break;
        }
        case Value::Type::Object: {
            out += '{';
            bool first = true;
            for (const auto& item : value.asObject()) {
                if (!first) out += ',';
                first = false;
                escape(out, item.first);
                out += ':';
                write(out, item.second);
            }
            out += '}';
            break;
        }
    }
}

}  // namespace

Value Parse(const std::string& text, std::size_t maxBytes) {
    if (text.size() > maxBytes) throw Error("JSON document is too large.");
    return Parser(text).document();
}

std::string Serialize(const Value& value) {
    std::string out;
    write(out, value);
    return out;
}

void RequireExactKeys(const Value& value, const std::vector<std::string>& keys, const char* what) {
    if (!value.isObject()) throw Error(std::string(what) + " must be a JSON object.");
    std::set<std::string> expected(keys.begin(), keys.end());
    std::set<std::string> actual;
    for (const auto& item : value.asObject()) actual.insert(item.first);
    if (expected != actual) throw Error(std::string(what) + " has missing or unexpected fields.");
}

}  // namespace json
}  // namespace tlp
