#pragma once

// Minimal declarations for NumericalOJ editor semantics. This header is never
// used to compile submissions; judging uses the real toolchain in Docker.
namespace std {
using size_t = decltype(sizeof(0));

template <class T> class allocator {};

class string {
public:
    using value_type = char;
    using iterator = char*;
    using const_iterator = const char*;
    size_t size() const noexcept;
    bool empty() const noexcept;
    void clear() noexcept;
    const char* c_str() const noexcept;
    char& operator[](size_t);
    const char& operator[](size_t) const;
};

template <class T, class Allocator = allocator<T>> class vector {
public:
    using value_type = T;
    using iterator = T*;
    using const_iterator = const T*;
    size_t size() const noexcept;
    bool empty() const noexcept;
    void clear() noexcept;
    void reserve(size_t);
    void resize(size_t);
    void push_back(const T&);
    void pop_back();
    T& front();
    T& back();
    T& operator[](size_t);
    iterator begin() noexcept;
    iterator end() noexcept;
};

template <class T, size_t Size> class array {
public:
    size_t size() const noexcept;
    bool empty() const noexcept;
    T& front();
    T& back();
    T& operator[](size_t);
    T* begin() noexcept;
    T* end() noexcept;
};

template <class T> class deque : public vector<T> {};
template <class T> class list : public vector<T> {};
template <class T> class queue {
public:
    size_t size() const;
    bool empty() const;
    T& front();
    T& back();
    void push(const T&);
    void pop();
};
template <class T> class stack {
public:
    size_t size() const;
    bool empty() const;
    T& top();
    void push(const T&);
    void pop();
};

template <class First, class Second> struct pair {
    First first;
    Second second;
};

template <class Key, class Value> class map {
public:
    size_t size() const noexcept;
    bool empty() const noexcept;
    void clear() noexcept;
    Value& operator[](const Key&);
};
template <class Key, class Value> class unordered_map : public map<Key, Value> {};
template <class Key> class set {
public:
    size_t size() const noexcept;
    bool empty() const noexcept;
    void clear() noexcept;
    void insert(const Key&);
};
template <class Key> class unordered_set : public set<Key> {};

template <class T> class optional {
public:
    bool has_value() const noexcept;
    T& value();
    explicit operator bool() const noexcept;
};
template <class T> class unique_ptr {
public:
    T* get() const noexcept;
    T& operator*() const;
    T* operator->() const noexcept;
};
template <class T> class shared_ptr : public unique_ptr<T> {};

template <class T> T&& move(T& value) noexcept;
template <class Iterator> void sort(Iterator first, Iterator last);
template <class Iterator, class Value> Iterator find(
    Iterator first,
    Iterator last,
    const Value& value
);
}  // namespace std
