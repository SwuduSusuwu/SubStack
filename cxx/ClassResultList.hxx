/* Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses) */
#pragma once
#ifndef INCLUDES_cxx_ClassResultList_hxx
#define INCLUDES_cxx_ClassResultList_hxx
//#include "ClassObject.hxx" /* Object */ /* TODO: fix "Initialization of non-aggregate type" */
#include "ClassPortableExecutable.hxx" /* FilePath FileBytecode FileHash */
#include <algorithm> /* std::search std::find std::set_intersection */
#include <cstddef> /* size_t */
#if PREFERENCE_IS_CSTR
#include <cstring> /* strlen memmem */
#endif /* PREFERENCE_IS_CSTR */
#include <tuple> /* std::tuple std::get */
#include <unordered_set> /* std::unordered_set */
#include <vector> /* std::vector */
namespace Susuwu {
typedef FileHash ResultListHash;
typedef FileBytecode ResultListBytecode; /* Should have structure of FileBytecode, but is not just for files, can use for UTF8/webpages, so have a new type for this */
typedef FilePath ResultListSignature; /* TODO: `typedef ResultListBytecode ResultListSignature; ResultListSignature("string literal");` */
typedef struct ResultList /* : Object */ { /* Lists of files (or pages) */
	const std::string getName() const {return "Susuwu::struct ResultList";}
	std::unordered_set<ResultListHash> hashes; /* Unique checksums of files (or pages), to avoid duplicates, plus to do fast checks for existance */
	std::vector<ResultListSignature> signatures; /* Smallest substrings (or regexes, or Universal Resource Locator) unique to this, has uses close to `hashes` but can match if files have small differences */
	std::vector<ResultListBytecode> bytecodes; /* Whole files (or webpages); uses lots of space, just populate this for signature synthesis (or training CNS). */
} ResultList;

template<class List>
const size_t listMaxSize(const List &list) {
#if PREFERENCE_IS_CSTR
	size_t max = 0;
	for(auto it = &list[0]; list.cend() != it; ++it) { const size_t temp = strlen(*it); if(temp > max) {max = temp;}}
	return max; /* WARNING! `strlen()` just does UTF8-strings/hex-strings; if binary, must use `it->size()` */
#else /* else !PREFERENCE_IS_CSTR */
	auto it = std::max_element(list.cbegin(), list.cend(), [](const auto &s, const auto &x) { return s.size() < x.size(); });
	return it->size();
#endif /* PREFERENCE_IS_CSTR else */
}

/* @pre @code std::is_sorted(list.cbegin(), list.cend()) && std::is_sorted(list2.cbegin(), list2.cend()) @endcode */
template<class List>
const List listIntersections(const List &list, const List &list2) {
	List intersections;
	std::set_intersection(list.cbegin(), list.cend(), list2.cbegin(), list2.cend(), std::back_inserter(intersections));
	return intersections;
}
template<class List>
const bool listsIntersect(const List &list, const List &list2) {
	return listIntersections(list, list2).size();
}

template<class List>
auto listFindValue(const List &list, const typename List::value_type &x) {
	return std::find(list.cbegin(), list.cend(), x);
}
template<class List>
const bool listHasValue(const List &list, const typename List::value_type &x) {
	return list.cend() != listFindValue(list, x);
}
template<class List>
/* @pre @code s < x @endcode */
auto listFindSubstr(const List &list, typename List::value_type::const_iterator s, typename List::value_type::const_iterator x) {
#pragma unroll
	for(const auto &value : list) {
		auto result = std::search(value.cbegin(), value.cend(), s, x, [](char ch1, char ch2) { return ch1 == ch2; });
		if(value.cend() != result) {
			return result;
		}
	}
	return list.back().cend();
}
template<class List>
/* @pre @code s < x @endcode */
const bool listHasSubstr(const List &list, typename List::value_type::const_iterator s, typename List::value_type::const_iterator x) {
	return list.back().cend() != listFindSubstr(list, s, x);
}
template<class List>
/* Usage: resultList.signatures.push_back({listProduceUniqueSubstr(resultList.bytecodes, bytecode)); */
const std::tuple<typename List::value_type::const_iterator, typename List::value_type::const_iterator> listProduceUniqueSubstr(const List &list, const typename List::value_type &value) {
	size_t smallest = value.size();
	auto retBegin = value.cbegin(), retEnd = value.cend();
	for(auto s = retBegin; value.cend() != s; ++s) {
		for(auto x = value.cend(); s != x; --x) {
			if((x - s) < smallest) {
				if(listHasSubstr(list, s, x)) {
					break;
				}
				smallest = x - s;
				retBegin = s, retEnd = x;
			}
		}
	} /* Incremental `for()` loops, is a slow method to produce unique substrings; should use binary searches, or look for the standard function which optimizes this. */
	return {retBegin, retEnd};
}
template<class List>
/* Usage: auto it = listOfSubstrFindMatch(resultList.signatures, bytecode)); if(it) {std::cout << "value matches ResultList.signatures[" << it << "]";} */
auto listOfSubstrFindMatch(const List &list, const typename List::value_type &x) {
	for(const auto &value : list) {
#if PREFERENCE_IS_CSTR
		auto result = memmem(&x[0], strlen(&x[0]), &value[0], strlen(&value[0]));
		if(NULL != result) {
#else /* !PREFERENCE_IS_CSTR */
		auto result = std::search(x.cbegin(), x.cend(), value.cbegin(), value.cend(), [](char ch1, char ch2) { return ch1 == ch2; });
		if(value.cend() != result) {
#endif /* !PREFERENCE_IS_CSTR */
			return result;
		}
	}
	return list.back().cend();
}
template<class List>
/* Usage: if(listOfSubstrHasMatch(resultList.signatures, bytecode)) {std::cout << "value matches ResultList.signatures";} */
const bool listOfSubstrHasMatch(const List &list, const typename List::value_type &x) {
	return list.back().cend() != listOfSubstrFindMatch(list, x);
}

template<class S>
const std::vector<S> explodeToList(const S &s, const S &token) {
	std::vector<S> list;
	for(auto x = s.cbegin(); s.cend() != x; ) {
		auto it = std::search(x, s.cend(), token.cbegin(), token.cend(), [](char ch1, char ch2) { return ch1 == ch2; });
		list.push_back(S(x, it));
		if(s.cend() == x) {
			return list;
		}
		x = it;
	}
	return list;
}
}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_ClassResultList_hxx */

