/* Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses) */
#pragma once
#ifndef INCLUDES_cxx_ClassResultList_hxx
#define INCLUDES_cxx_ClassResultList_hxx
//#include "ClassObject.hxx" /* Object */ /* TODO: fix "Initialization of non-aggregate type" */
#include "ClassPortableExecutable.hxx" /* FilePath FileBytecode FileHash */
#include "ClassSha2.hxx" /* sha2 */
#include <algorithm> /* std::search std::find std::set_intersection */
#include <cstddef> /* size_t */
#if PREFERENCE_IS_CSTR
#include <cstring> /* strlen memmem */
#endif /* PREFERENCE_IS_CSTR */
#include <iomanip> /* std::hex std::dec */
#include <ostream> /* std::ostream */
#include <tuple> /* std::tuple std::get */
#include <unordered_set> /* std::unordered_set */
#include <vector> /* std::vector */
namespace Susuwu {
typedef FileHash ResultListHash;
typedef FileBytecode ResultListBytecode; /* Should have structure of FileBytecode, but is not just for files, can use for UTF8/webpages, so have a new type for this */
typedef FilePath ResultListSignature; /* TODO: `typedef ResultListBytecode ResultListSignature; ResultListSignature("string literal");` */
typedef struct ResultList /* : Object */ { /* Lists of {metadata, executables (or pages)} */
	const std::string getName() const {return "Susuwu::struct ResultList";}
	std::unordered_set<ResultListHash> hashes; /* Checksums of executables (or pages); to avoid duplicates, plus to do constant ("O(1)") test for which executables (or pages) exists */
	std::vector<ResultListSignature> signatures; /* Smallest substrings (or regexes, or Universal Resource Locators) which can identify `bytecodes`; has uses close to `hashes`, but can match if executables (or pages) have small differences */
	std::vector<ResultListBytecode> bytecodes; /* Whole executables (for `VirusAnalysis`) or webpages (for `AssistantCns`); huge disk usage, just load this for signature synthesis (or CNS backpropagation). */
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

template<class List>
void listDumpTo(const List &list, std::ostream &os, const bool whitespace, const bool pascalValues) {
	size_t index = 0;
	os << '{';
	for(const auto &value : list) {
		if(0 != index) {
			os << ',';
		}
		if(whitespace) {
			os << std::endl << '\t';
		}
		os << index++;
		if(pascalValues) {
				os << value.size() << value;
		} else {
			os << "=>0x";
			for(char ch : value) {
				os << std::hex << static_cast<int>(ch);
			}
			os << std::dec;
		}
	}
	if(whitespace) {
		os << "\n};" << std::endl;
	} else {
		os << "};";
	}
}
template<class List>
void resultListDumpTo(const List &list, std::ostream &os, const bool whitespace, const bool pascalValues) {
	os << "list.hashes" << (whitespace ? " = " : "=");
	listDumpTo(list.hashes, os, whitespace, pascalValues);
	os << "list.signatures" << (whitespace ? " = " : "=");
	listDumpTo(list.signatures, os, whitespace, pascalValues);
	os << "list.bytecodes" << (whitespace ? " = " : "=");
	listDumpTo(list.bytecodes, os, whitespace, pascalValues);
}

template<class List, class List2>
/*	@pre @code !(list.empty() || hashes.full()) @endcode
 *	@post @code !hashes.empty() @endcode */
void listToHashes(const List &list /* ResultList::bytecodes or ResultList::hex*/, List2 &hashes /* ResultList::hashess */) {
	for(const auto &value : list) {
		hashes.insert(sha2(value));
	}
}
/* Usage: if ResultList was not produced with hashes */
static void resultListProduceHashes(ResultList &resultList) {
	listToHashes(resultList.bytecodes, resultList.hashes);
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
/* return list's const_iterator to first instance of x, or list.cend() (if not found) */
auto listFindValue(const List &list, const typename List::value_type &x) {
	return std::find(list.cbegin(), list.cend(), x);
}
template<class List>
const bool listHasValue(const List &list, const typename List::value_type &x) {
	return list.cend() != listFindValue(list, x);
}

template<class List>
const typename List::value_type::const_iterator listDefaultIterator = typename List::value_type::const_iterator(); /* Equates to "Not found" */
template<class List>
/* return list's const_iterator to first instance of Substr{s, x}, or default iterator (if not found)
 * @pre @code s < x @endcode */
typeof listDefaultIterator<List> listFindSubstr(const List &list, typename List::value_type::const_iterator s, typename List::value_type::const_iterator x) {
#pragma unroll
	for(const auto &value : list) {
		auto result = std::search(value.cbegin(), value.cend(), s, x, [](char ch1, char ch2) { return ch1 == ch2; });
		if(value.cend() != result) {
			return result;
		}
	}
	return listDefaultIterator<List>;
}
template<class List>
/* @pre @code s < x @endcode */
const bool listHasSubstr(const List &list, typename List::value_type::const_iterator s, typename List::value_type::const_iterator x) {
	return listDefaultIterator<List> != listFindSubstr(list, s, x);
}
template<class List>
/* Returns shortest substr from `value`, which is not found in `list`
 * Usage: resultList.signatures.push_back({listProduceSignature(resultList.bytecodes, bytecode)); */
const std::tuple<typename List::value_type::const_iterator, typename List::value_type::const_iterator> listProduceSignature(const List &list, const typename List::value_type &value) {
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
	} /* Incremental `for()` loops, is O(n^2 * m) complex formula to produce signatures; should use binary searches, or look for the Standard Template Lib (or Boost) function which optimizes this. */
	return {retBegin, retEnd};
}
template<class List>
/* Usage: auto it = listFindSignatureOfValue(resultList.signatures, input)); if(it) {std::cout << "input has resultList.signatures[" << std::string(it) << "]";} */
typeof listDefaultIterator<List> listFindSignatureOfValue(const List &list, const typename List::value_type &x) {
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
	return listDefaultIterator<List>;
}
template<class List>
/* Usage: if(listHasSignatureOfValue(resultList.signatures, input)) {std::cout << "input has signature from ResultList.signatures";} */
const bool listHasSignatureOfValue(const List &list, const typename List::value_type &x) {
	return listDefaultIterator<List> != listFindSignatureOfValue(list, x);
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

