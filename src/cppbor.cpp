/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cppbor.h"

#include <inttypes.h>
#include <openssl/sha.h>

#include "cppbor_parse.h"

using std::string;
using std::vector;

#ifndef __TRUSTY__
#include <android-base/logging.h>
#define LOG_TAG "CppBor"
#else
#define CHECK(x) (void)(x)
#endif

namespace cppbor {

namespace {

template <typename T, typename Iterator, typename = std::enable_if<std::is_unsigned<T>::value>>
Iterator writeBigEndian(T value, Iterator pos) {
    for (unsigned i = 0; i < sizeof(value); ++i) {
        *pos++ = static_cast<uint8_t>(value >> (8 * (sizeof(value) - 1)));
        value = static_cast<T>(value << 8);
    }
    return pos;
}

template <typename T, typename = std::enable_if<std::is_unsigned<T>::value>>
void writeBigEndian(T value, std::function<void(uint8_t)>& cb) {
    for (unsigned i = 0; i < sizeof(value); ++i) {
        cb(static_cast<uint8_t>(value >> (8 * (sizeof(value) - 1))));
        value = static_cast<T>(value << 8);
    }
}

bool cborAreAllElementsNonCompound(const CompoundItem* compoundItem) {
    if (compoundItem->type() == ARRAY) {
        const Array* array = compoundItem->asArray();
        for (size_t n = 0; n < array->size(); n++) {
            const Item* entry = (*array)[n].get();
            switch (entry->type()) {
                case ARRAY:
                case MAP:
                    return false;
                default:
                    break;
            }
        }
    } else {
        const Map* map = compoundItem->asMap();
        for (size_t n = 0; n < map->size(); n++) {
            auto [keyEntry, valueEntry] = (*map)[n];
            switch (keyEntry->type()) {
                case ARRAY:
                case MAP:
                    return false;
                default:
                    break;
            }
            switch (valueEntry->type()) {
                case ARRAY:
                case MAP:
                    return false;
                default:
                    break;
            }
        }
    }
    return true;
}

bool prettyPrintInternal(const Item* item, string& out, size_t indent, size_t maxBStrSize,
                         const vector<string>& mapKeysToNotPrint) {
    if (!item) {
        out.append("<NULL>");
        return false;
    }

    char buf[80];

    string indentString(indent, ' ');

    switch (item->type()) {
        case UINT:
            snprintf(buf, sizeof(buf), "%" PRIu64, item->asUint()->unsignedValue());
            out.append(buf);
            break;

        case NINT:
            snprintf(buf, sizeof(buf), "%" PRId64, item->asNint()->value());
            out.append(buf);
            break;

        case BSTR: {
            const Bstr* bstr = item->asBstr();
            const vector<uint8_t>& value = bstr->value();
            if (value.size() > maxBStrSize) {
                unsigned char digest[SHA_DIGEST_LENGTH];
                SHA_CTX ctx;
                SHA1_Init(&ctx);
                SHA1_Update(&ctx, value.data(), value.size());
                SHA1_Final(digest, &ctx);
                char buf2[SHA_DIGEST_LENGTH * 2 + 1];
                for (size_t n = 0; n < SHA_DIGEST_LENGTH; n++) {
                    snprintf(buf2 + n * 2, 3, "%02x", digest[n]);
                }
                snprintf(buf, sizeof(buf), "<bstr size=%zd sha1=%s>", value.size(), buf2);
                out.append(buf);
            } else {
                out.append("{");
                for (size_t n = 0; n < value.size(); n++) {
                    if (n > 0) {
                        out.append(", ");
                    }
                    snprintf(buf, sizeof(buf), "0x%02x", value[n]);
                    out.append(buf);
                }
                out.append("}");
            }
        } break;

        case TSTR:
            out.append("'");
            {
                // TODO: escape "'" characters
                out.append(item->asTstr()->value().c_str());
            }
            out.append("'");
            break;

        case ARRAY: {
            const Array* array = item->asArray();
            if (array->size() == 0) {
                out.append("[]");
            } else if (cborAreAllElementsNonCompound(array)) {
                out.append("[");
                for (size_t n = 0; n < array->size(); n++) {
                    if (!prettyPrintInternal((*array)[n].get(), out, indent + 2, maxBStrSize,
                                             mapKeysToNotPrint)) {
                        return false;
                    }
                    out.append(", ");
                }
                out.append("]");
            } else {
                out.append("[\n" + indentString);
                for (size_t n = 0; n < array->size(); n++) {
                    out.append("  ");
                    if (!prettyPrintInternal((*array)[n].get(), out, indent + 2, maxBStrSize,
                                             mapKeysToNotPrint)) {
                        return false;
                    }
                    out.append(",\n" + indentString);
                }
                out.append("]");
            }
        } break;

        case MAP: {
            const Map* map = item->asMap();

            if (map->size() == 0) {
                out.append("{}");
            } else {
                out.append("{\n" + indentString);
                for (size_t n = 0; n < map->size(); n++) {
                    out.append("  ");

                    auto [map_key, map_value] = (*map)[n];

                    if (!prettyPrintInternal(map_key.get(), out, indent + 2, maxBStrSize,
                                             mapKeysToNotPrint)) {
                        return false;
                    }
                    out.append(" : ");
                    if (map_key->type() == TSTR &&
                        std::find(mapKeysToNotPrint.begin(), mapKeysToNotPrint.end(),
                                  map_key->asTstr()->value()) != mapKeysToNotPrint.end()) {
                        out.append("<not printed>");
                    } else {
                        if (!prettyPrintInternal(map_value.get(), out, indent + 2, maxBStrSize,
                                                 mapKeysToNotPrint)) {
                            return false;
                        }
                    }
                    out.append(",\n" + indentString);
                }
                out.append("}");
            }
        } break;

        case SEMANTIC: {
            const Semantic* semantic = item->asSemantic();
            snprintf(buf, sizeof(buf), "tag %" PRIu64 " ", semantic->value());
            out.append(buf);
            prettyPrintInternal(semantic->child().get(), out, indent, maxBStrSize,
                                mapKeysToNotPrint);
        } break;

        case SIMPLE:
            const Bool* asBool = item->asSimple()->asBool();
            const Null* asNull = item->asSimple()->asNull();
            if (asBool != nullptr) {
                out.append(asBool->value() ? "true" : "false");
            } else if (asNull != nullptr) {
                out.append("null");
            } else {
                LOG(ERROR) << "Only boolean/null is implemented for SIMPLE";
                return false;
            }
            break;
    }

    return true;
}

}  // namespace

size_t headerSize(uint64_t addlInfo) {
    if (addlInfo < ONE_BYTE_LENGTH) return 1;
    if (addlInfo <= std::numeric_limits<uint8_t>::max()) return 2;
    if (addlInfo <= std::numeric_limits<uint16_t>::max()) return 3;
    if (addlInfo <= std::numeric_limits<uint32_t>::max()) return 5;
    return 9;
}

uint8_t* encodeHeader(MajorType type, uint64_t addlInfo, uint8_t* pos, const uint8_t* end) {
    size_t sz = headerSize(addlInfo);
    if (end - pos < static_cast<ssize_t>(sz)) return nullptr;
    switch (sz) {
        case 1:
            *pos++ = type | static_cast<uint8_t>(addlInfo);
            return pos;
        case 2:
            *pos++ = type | ONE_BYTE_LENGTH;
            *pos++ = static_cast<uint8_t>(addlInfo);
            return pos;
        case 3:
            *pos++ = type | TWO_BYTE_LENGTH;
            return writeBigEndian(static_cast<uint16_t>(addlInfo), pos);
        case 5:
            *pos++ = type | FOUR_BYTE_LENGTH;
            return writeBigEndian(static_cast<uint32_t>(addlInfo), pos);
        case 9:
            *pos++ = type | EIGHT_BYTE_LENGTH;
            return writeBigEndian(addlInfo, pos);
        default:
            CHECK(false);  // Impossible to get here.
            return nullptr;
    }
}

void encodeHeader(MajorType type, uint64_t addlInfo, EncodeCallback encodeCallback) {
    size_t sz = headerSize(addlInfo);
    switch (sz) {
        case 1:
            encodeCallback(type | static_cast<uint8_t>(addlInfo));
            break;
        case 2:
            encodeCallback(type | ONE_BYTE_LENGTH);
            encodeCallback(static_cast<uint8_t>(addlInfo));
            break;
        case 3:
            encodeCallback(type | TWO_BYTE_LENGTH);
            writeBigEndian(static_cast<uint16_t>(addlInfo), encodeCallback);
            break;
        case 5:
            encodeCallback(type | FOUR_BYTE_LENGTH);
            writeBigEndian(static_cast<uint32_t>(addlInfo), encodeCallback);
            break;
        case 9:
            encodeCallback(type | EIGHT_BYTE_LENGTH);
            writeBigEndian(addlInfo, encodeCallback);
            break;
        default:
            CHECK(false);  // Impossible to get here.
    }
}

bool Item::operator==(const Item& other) const& {
    if (type() != other.type()) return false;
    switch (type()) {
        case UINT:
            return *asUint() == *(other.asUint());
        case NINT:
            return *asNint() == *(other.asNint());
        case BSTR:
            return *asBstr() == *(other.asBstr());
        case TSTR:
            return *asTstr() == *(other.asTstr());
        case ARRAY:
            return *asArray() == *(other.asArray());
        case MAP:
            return *asMap() == *(other.asMap());
        case SIMPLE:
            return *asSimple() == *(other.asSimple());
        case SEMANTIC:
            return *asSemantic() == *(other.asSemantic());
        default:
            CHECK(false);  // Impossible to get here.
            return false;
    }
}

Nint::Nint(int64_t v) : mValue(v) {
    CHECK(v < 0);
}

bool Simple::operator==(const Simple& other) const& {
    if (simpleType() != other.simpleType()) return false;

    switch (simpleType()) {
        case BOOLEAN:
            return *asBool() == *(other.asBool());
        case NULL_T:
            return true;
        default:
            CHECK(false);  // Impossible to get here.
            return false;
    }
}

uint8_t* Bstr::encode(uint8_t* pos, const uint8_t* end) const {
    pos = encodeHeader(mValue.size(), pos, end);
    if (!pos || end - pos < static_cast<ptrdiff_t>(mValue.size())) return nullptr;
    return std::copy(mValue.begin(), mValue.end(), pos);
}

void Bstr::encodeValue(EncodeCallback encodeCallback) const {
    for (auto c : mValue) {
        encodeCallback(c);
    }
}

uint8_t* Tstr::encode(uint8_t* pos, const uint8_t* end) const {
    pos = encodeHeader(mValue.size(), pos, end);
    if (!pos || end - pos < static_cast<ptrdiff_t>(mValue.size())) return nullptr;
    return std::copy(mValue.begin(), mValue.end(), pos);
}

void Tstr::encodeValue(EncodeCallback encodeCallback) const {
    for (auto c : mValue) {
        encodeCallback(static_cast<uint8_t>(c));
    }
}

bool CompoundItem::operator==(const CompoundItem& other) const& {
    return type() == other.type()             //
           && addlInfo() == other.addlInfo()  //
           // Can't use vector::operator== because the contents are pointers.  std::equal lets us
           // provide a predicate that does the dereferencing.
           && std::equal(mEntries.begin(), mEntries.end(), other.mEntries.begin(),
                         [](auto& a, auto& b) -> bool { return *a == *b; });
}

uint8_t* CompoundItem::encode(uint8_t* pos, const uint8_t* end) const {
    pos = encodeHeader(addlInfo(), pos, end);
    if (!pos) return nullptr;
    for (auto& entry : mEntries) {
        pos = entry->encode(pos, end);
        if (!pos) return nullptr;
    }
    return pos;
}

void CompoundItem::encode(EncodeCallback encodeCallback) const {
    encodeHeader(addlInfo(), encodeCallback);
    for (auto& entry : mEntries) {
        entry->encode(encodeCallback);
    }
}

void Map::assertInvariant() const {
    CHECK(mEntries.size() % 2 == 0);
}

bool mapKeyLess(const std::pair<std::unique_ptr<Item>&, std::unique_ptr<Item>&>& a,
                const std::pair<std::unique_ptr<Item>&, std::unique_ptr<Item>&>& b) {
    auto keyA = a.first->encode();
    auto keyB = b.first->encode();

    // CBOR map canonicalization rules are:

    // 1. If two keys have different lengths, the shorter one sorts earlier.
    if (keyA.size() < keyB.size()) return true;
    if (keyA.size() > keyB.size()) return false;

    // 2. If two keys have the same length, the one with the lower value in
    // (byte-wise) lexical order sorts earlier.
    return std::lexicographical_compare(keyA.begin(), keyA.end(), keyB.begin(), keyB.end());
}

Map& Map::canonicalize() & {
    assertInvariant();

    if (size() < 2) {
        // Empty or single-entry map; no need to reorder.
        return *this;
    }

    // The entries of a Map are stored in a flat vector.  We can't easily apply
    // std::sort on that, so instead we move all of the entries into a vector of
    // std::pair, sort that, then move all of the entries back into the original
    // flat vector.
    vector<std::pair<std::unique_ptr<Item>, std::unique_ptr<Item>>> temp;
    temp.reserve(size());

    for (size_t i = 0; i < mEntries.size() - 1; i += 2) {
        temp.push_back({std::move(mEntries[i]), std::move(mEntries[i + 1])});
    }

    std::sort(temp.begin(), temp.end(), mapKeyLess);

    mEntries.resize(0);
    mEntries.reserve(temp.size() * 2);  // Should be a NOP since capacity should be unchanged.
    for (auto& entry : temp) {
        mEntries.push_back(std::move(entry.first));
        mEntries.push_back(std::move(entry.second));
    }

    return *this;
}

std::unique_ptr<Item> Map::clone() const {
    assertInvariant();
    auto res = std::make_unique<Map>();
    for (size_t i = 0; i < mEntries.size(); i += 2) {
        res->add(mEntries[i]->clone(), mEntries[i + 1]->clone());
    }
    return res;
}

std::unique_ptr<Item> Array::clone() const {
    auto res = std::make_unique<Array>();
    for (size_t i = 0; i < mEntries.size(); i++) {
        res->add(mEntries[i]->clone());
    }
    return res;
}

void Semantic::assertInvariant() const {
    CHECK(mEntries.size() == 1);
}

string prettyPrint(const Item* item, size_t maxBStrSize, const vector<string>& mapKeysToNotPrint) {
    string out;
    prettyPrintInternal(item, out, 0, maxBStrSize, mapKeysToNotPrint);
    return out;
}
string prettyPrint(const vector<uint8_t>& encodedCbor, size_t maxBStrSize,
                   const vector<string>& mapKeysToNotPrint) {
    auto [item, _, message] = parse(encodedCbor);
    if (item == nullptr) {
        LOG(ERROR) << "Data to pretty print is not valid CBOR: " << message;
        return "";
    }

    return prettyPrint(item.get(), maxBStrSize, mapKeysToNotPrint);
}

}  // namespace cppbor
