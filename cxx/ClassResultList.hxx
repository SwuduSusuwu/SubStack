/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#pragma once
#ifndef INCLUDES_cxx_ClassResultList_hxx
#define INCLUDES_cxx_ClassResultList_hxx
#include <string> /* std::string */
#include <vector> /* std::vector */
#include <algorithm> /* std::search std::find std::set_intersection */
#include <unordered_set> /* std::unordered_set */
#include <ctype.h> /* size_t */
#if PREFERENCE_IS_CSTR
#include <string.h> /* strlen */
#endif /* PREFERENCE_IS_CSTR */
#include "ClassPortableExecutable.hxx" /* FilePath FileBytecode FileHash*/
namespace Susuwu {
typedef FileHash ResultListHash;
typedef FileBytecode ResultListBytecode; /* Should have structure of FileBytecode, but is not just for files, can use for UTF8/webpages, so have a new type for this */
typedef FilePath ResultListSignature; /* TODO: `typedef ResultListBytecode ResultListSignature; ResultListSignature("string literal");` */
typedef struct ResultList { /* Lists of files (or pages) */
	std::unordered_set<ResultListHash> hashes; /* Unique checksums of files (or pages), to avoid duplicates, plus to do fast checks for existance */
	std::vector<ResultListSignature> signatures; /* Smallest substrings (or regexes, or Universal Resource Locator) unique to this, has uses close to `hashes` but can match if files have small differences */
	std::vector<ResultListBytecode> bytecodes; /* Whole files (or webpages); uses lots of space, just populate this for signature synthesis (or training CNS). */
} ResultList;
const bool resultListHashesHas(const ResultList &list, ResultList &caches, const std::string &bytecode);

template<class List>
const size_t maxOfSizes(const List &list) {
#if PREFERENCE_IS_CSTR
	size_t max = 0;
	for(auto it = &list[0]; list.end() != it; ++it) { const size_t temp = strlen(*it); if(temp > max) {max = temp;}}
	return max; /* WARNING! `strlen()` just does UTF8-strings/hex-strings; if binary, must use `it->size()` */
#else /* else !PREFERENCE_IS_CSTR */
	auto it = std::max_element(list.begin(), list.end(), [](const auto &s, const auto &x) { return s.size() < x.size(); });
	return it->size();
#endif /* PREFERENCE_IS_CSTR else */
}

/* @pre @code std::is_sorted(list.begin(), list.end()) && std::is_sorted(list2.begin(), list2.end()) @endcode */
template<class List>
const List listIntersections(const List &list, const List &list2) {
	List intersections;
	std::set_intersection(list.begin(), list.end(), list2.begin(), list2.end(), std::back_inserter(intersections));
	return intersections;
}
template<class List>
const bool listsIntersect(const List &list, const List &list2) {
	return listIntersections(list, list2).size();
}

template<class List>
auto listFind(const List &list, const typename List::value_type &x) {
	return std::find(list.begin(), list.end(), x);
}
template<class List>
const bool listHas(const List &list, const typename List::value_type &x) {
	return list.end() != listFind(list, x);
}
template<class List>
const bool listHas(const List &list, typename List::value_type::const_iterator s, typename List::value_type::const_iterator x) {
	for(auto chars : list) {
		if(chars.end() != std::search(chars.begin(), chars.end(), s, x, [](char ch1, char ch2) { return ch1 == ch2; })) {
			return true;
		}
	}
	return false;
}

template<class S>
const std::vector<S> explodeToList(const S &s, const S &token) {
	std::vector<S> list;
	for(auto x = s.begin(); s.end() != x; ) {
		auto it = std::search(x, s.end(), token.begin(), token.end(), [](char ch1, char ch2) { return ch1 == ch2; });
		list.push_back(S(x, it));
		if(s.end() == x) {
			return list;
		}
		x = it;
	}
	return list;
}

template<class List>
const std::tuple<std::string::const_iterator, std::string::const_iterator> smallestUniqueSubstr(const std::string &chars, const List &list) {
	size_t smallest = chars.size();
	auto retBegin = chars.begin(), retEnd = chars.end();
	for(auto s = retBegin; chars.end() != s; ++s) {
		for(auto x = chars.end() - 1; s != x; --x) {
			if(smallest <= x - s || listHas(list, s, x)) {
				break;
			}
			smallest = x - s;
			retBegin = s, retEnd = x;
		}
	} /* Incremental `for()` loops, is a slow method to produce unique substrings; should use binary searches, or quadratic searches, or look for the standard function which optimizes this. */
	return {retBegin, retEnd};
}
}; /* namespace Susuwu */
#endif /* ndef INCLUDED_cxx_ClassResultList_hxx */

